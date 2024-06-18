def install_package(package, version="upgrade", index_url='https://mirrors.aliyun.com/pypi/simple/'):
    from sys import executable
    from subprocess import check_call
    result = False
    try:
        if version.lower() == "upgrade":
            result = check_call([executable, "-m", "pip", "install", package, "--upgrade", "-i", index_url])
        else:
            from pkg_resources import get_distribution
            current_package_version = None
            try:
                current_package_version = get_distribution(package)
            except Exception:
                pass
            if current_package_version is None or current_package_version != version:
                installation_sign = "==" if ">=" not in version else ""
                result = check_call([executable, "-m", "pip", "install", package + installation_sign + version, "-i", index_url])
    except Exception as e:
        print(e)
        result = -1
    return result    
def check_package(package):
    from importlib import import_module
    try:
        import_module(package)
        return True
    except ImportError:
        return False 
def check_install_package(packages):
    for package in packages:
        if not check_package(package): 
            install_package(package)