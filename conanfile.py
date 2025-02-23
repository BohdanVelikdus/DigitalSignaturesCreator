from conan import ConanFile

class Recepient(ConanFile):
    settings = "os", "compiler","build_type", "arch"
    generators = "CMakeDeps", "CMakeToolchain"

    def requirements(self):
        self.requires("openssl/3.4.1")