#include "preprocess/artifacts.h"
int main(int argc, char **argv) {
    try {
        shkr::Config c(argc, argv);
        shkr::preprocess(c);
        return 0;
    } catch (const std::exception &e) {
        std::cerr << "ERROR: " << e.what() << '\n';
        return 1;
    }
}
