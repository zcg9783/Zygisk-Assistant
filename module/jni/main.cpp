#include <unistd.h>
#include <sched.h>
#include <sys/mount.h>
#include <fstream>
#include <string>
#include <vector>
#include <sstream>

#include <cstdint>
#include <functional>

#include "zygisk.hpp"
#include "logging.hpp"
#include "utils.hpp"
#include "modules.hpp"
#include "fd_reopener.hpp"

using zygisk::Api;
using zygisk::AppSpecializeArgs;
using zygisk::ServerSpecializeArgs;

static std::function<void()> callbackFunction = []() {};

/*
 * [What's the purpose of this hook?]
 * Hooking unshare is necessary to stop Zygote from calling unshare a second time,
 * because that breaks the FDs. We handle this by reopening FDs,
 * allowing us to call unshare twice safely in our callback.
 *
 * [Doesn't Android already call unshare?]
 * Android's use of unshare changes with each major version, so we always call unshare
 * in preAppSpecialize.
 * > Android 5: Sometimes calls unshare
 * > Android 6: Always calls unshare
 * > Android 7-11: Sometimes calls unshare
 * > Android 12-14: Always calls unshare
 */
DCL_HOOK_FUNC(static int, unshare, int flags)
{
    callbackFunction();
    // Do not allow CLONE_NEWNS.
    flags &= ~(CLONE_NEWNS);
    if (!flags)
    {
        // If CLONE_NEWNS was the only flag, skip the call.
        errno = 0;
        return 0;
    }
    return old_unshare(flags);
}

/*
 * [What's the purpose of this hook?]
 * Hooking setresuid ensures we can execute code while we still have CAP_SYS_ADMIN,
 * which is necessary for some operations.
 * This hook is necessary because setresuid is called unconditionally,
 * and we need to perform actions before this syscall.
 */
DCL_HOOK_FUNC(static int, setresuid, uid_t ruid, uid_t euid, uid_t suid)
{
    callbackFunction();
    return old_setresuid(ruid, euid, suid);
}

/*
 * [Why is this function needed?]
 * This function unconditionally calls unshare to create a new mount namespace.
 * It ensures that the new namespace is isolated but still allows propagation of mount
 * events from the parent namespace by setting the root as MS_SLAVE.
 */
static bool new_mount_ns()
{
    /*
     * Unconditional unshare.
     */
    ASSERT_DO(new_mount_ns, old_unshare(CLONE_NEWNS) != -1, return false);

    /*
     * Mount the app mount namespace's root as MS_SLAVE, so every mount/umount from
     * Zygote shared pre-specialization namespace is propagated to this one.
     */
    ASSERT_DO(new_mount_ns, mount("rootfs", "/", NULL, (MS_SLAVE | MS_REC), NULL) != -1, return false);
    return true;
}

/*
 * [Helper function to read denylist from file]
 * Reads package names from /system/etc/denylist.txt
 * File format: one package name per line, comments start with #
 */
static bool isPackageInDenylist(const char* packageName)
{
    if (!packageName) {
        return false;
    }
    
    std::ifstream file("/system/etc/denylist.txt");
    if (!file.is_open()) {
        LOGD("denylist.txt not found or cannot be opened");
        return false;
    }
    
    std::string line;
    while (std::getline(file, line)) {
        // Remove leading/trailing whitespace
        line.erase(0, line.find_first_not_of(" \t"));
        line.erase(line.find_last_not_of(" \t") + 1);
        
        // Skip empty lines and comments
        if (line.empty() || line[0] == '#') {
            continue;
        }
        
        // Compare package name
        if (line == packageName) {
            LOGD("Package %s found in denylist", packageName);
            file.close();
            return true;
        }
    }
    
    file.close();
    return false;
}

/*
 * [Helper function to extract package name from app_data_dir]
 * Extracts package name from app_data_dir path like /data/user/0/com.example.app
 */
static std::string extractPackageName(const char* app_data_dir)
{
    if (!app_data_dir) {
        return "";
    }
    
    std::string path(app_data_dir);
    
    // Find the last slash
    size_t lastSlash = path.find_last_of('/');
    if (lastSlash == std::string::npos) {
        return "";
    }
    
    // Extract package name (everything after last slash)
    return path.substr(lastSlash + 1);
}

class ZygiskModule : public zygisk::ModuleBase
{
public:
    void onLoad(Api *api, JNIEnv *env) override
    {
        this->api = api;
        this->env = env;
    }

    void preAppSpecialize(AppSpecializeArgs *args) override
    {
        api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);

        uint32_t flags = api->getFlags();
        bool isRoot = (flags & zygisk::StateFlag::PROCESS_GRANTED_ROOT) != 0;
        bool isChildZygote = args->is_child_zygote != NULL && *args->is_child_zygote;
        
        // Extract package name from app_data_dir
        std::string packageName = extractPackageName(args->app_data_dir);
        bool isPackageDenied = false;
        
        if (!packageName.empty()) {
            isPackageDenied = isPackageInDenylist(packageName.c_str());
        } else {
            LOGD("Cannot extract package name from app_data_dir: %s", args->app_data_dir);
        }
        
        // Skip if: root process, package not in denylist, or not a user app
        if (isRoot || !isPackageDenied || !Utils::isUserAppUID(args->uid))
        {
            LOGD("Skipping ppid=%d uid=%d package=%s isChildZygote=%d", 
                 getppid(), args->uid, packageName.c_str(), isChildZygote);
            return;
        }
        
        LOGD("Processing ppid=%d uid=%d package=%s isChildZygote=%d", 
             getppid(), args->uid, packageName.c_str(), isChildZygote);

        ASSERT_DO(preAppSpecialize, hookPLTByName("libandroid_runtime.so", "unshare", new_unshare, &old_unshare), return);
        ASSERT_DO(preAppSpecialize, hookPLTByName("libandroid_runtime.so", "setresuid", new_setresuid, &old_setresuid), return);

        int companionFd = -1;
        ASSERT_LOG(preAppSpecialize, (companionFd = api->connectCompanion()) != -1);
        ASSERT_LOG(preAppSpecialize, companionFd != -1 && api->exemptFd(companionFd));

        callbackFunction = [fd = companionFd]()
        {
            // Call only once per process.
            callbackFunction = []() {};
            FDReopener::ScopedRegularReopener srr;
            
            if (!new_mount_ns())
                return;

            bool result = false;
            if (fd != -1)
            {
                do
                {
                    pid_t pid = getpid();
                    ASSERT_DO(callbackFunction, write(fd, &pid, sizeof(pid)) == sizeof(pid), break);
                    ASSERT_DO(callbackFunction, read(fd, &result, sizeof(result)) == sizeof(result), break);
                } while (false);
                close(fd);
            }

            if (result)
                LOGD("Invoking the companion was successful.");
            else
            {
                LOGW("Invoking the companion failed. Functionality will be limited in Zygote context!");
                doUnmount();
            }

            doHideZygisk();
        };
    }

    void preServerSpecialize(ServerSpecializeArgs *args) override
    {
        api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
    }

    void postAppSpecialize(const AppSpecializeArgs *args) override
    {
        if (old_unshare != nullptr)
            ASSERT_LOG(postAppSpecialize, hookPLTByName("libandroid_runtime.so", "unshare", old_unshare));
        if (old_setresuid != nullptr)
            ASSERT_LOG(postAppSpecialize, hookPLTByName("libandroid_runtime.so", "setresuid", old_setresuid));
    }

    template <typename T>
    bool hookPLTByName(const std::string &libName, const std::string &symbolName, T *hookFunction, T **originalFunction = nullptr)
    {
        return Utils::hookPLTByName(api, libName, symbolName, (void *)hookFunction, (void **)originalFunction) && api->pltHookCommit();
    }

private:
    Api *api;
    JNIEnv *env;
};

void zygisk_companion_handler(int fd)
{
    pid_t pid;
    ASSERT_DO(zygisk_companion_handler, read(fd, &pid, sizeof(pid)) == sizeof(pid), return);
    LOGD("zygisk_companion_handler processing namespace of pid=%d", pid);

    // setns requires the caller to be single-threaded
    bool result = WIFEXITED(Utils::forkAndInvoke(
        [pid]()
        {
            ASSERT_DO(zygisk_companion_handler, Utils::switchMountNS(pid), return 1);
            doUnmount();
            doRemount();
            doMrProp();
            return 0;
        }));

    ASSERT_LOG(zygisk_companion_handler, write(fd, &result, sizeof(result)) == sizeof(result));
}

REGISTER_ZYGISK_MODULE(ZygiskModule)
REGISTER_ZYGISK_COMPANION(zygisk_companion_handler)