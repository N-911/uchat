#include "../inc/libmx.h"

bool mx_isdigit(char c) {
    return c > 47 && c < 58 ? 1 : 0;
}
