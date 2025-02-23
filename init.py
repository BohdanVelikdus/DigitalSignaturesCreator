import subprocess
import os

def run_conan(os_type_str):
    subprocess.run([
        "conan", "install", ".", 
        "--build=missing", 
        "--output-folder=./external/dependencies", 
        "--profile", f"./external/profiles/{os_type_str}_debug.profile",
        "--settings", "build_type=Release"
    ], check=True)
    
    subprocess.run([
        "conan", "install", ".", 
        "--build=missing", 
        "--output-folder=./external/dependencies", 
        "--profile", f"./external/profiles/{os_type_str}_release.profile",
        "--settings", "build_type=Debug"
    ], check=True)
    return

if __name__== "__main__":
    if os.name == "nt":
        print("windows")
        run_conan("win")
    elif os.name == "posix":
        run_conan("unix")
