#include "preprocess/artifacts.h"
int main(int argc, char **argv) {
    try {
        shks::Config c(argc, argv);
        shks::preprocess(c);
        return 0;
    } catch (const std::exception &e) {
        std::cerr << "ERROR: " << e.what() << '\n';
        return 1;
    }
}
