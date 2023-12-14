#ifndef ENCRYPTION_COMMON_MACROS_H
#define ENCRYPTION_COMMON_MACROS_H

#include <cstdint>

#define NO_COPY_CTOR(TypeName) TypeName(const TypeName &) = delete
#define NO_COPY_OPERATOR(TypeName) TypeName &operator=(const TypeName &) = delete

#define NO_MOVE_CTOR(TypeName) TypeName(TypeName &&) = delete
#define NO_MOVE_OPERATOR(TypeName) TypeName &operator=(TypeName &&) = delete

#define NO_COPY_SEMANTIC(TypeName) \
    NO_COPY_CTOR(TypeName);        \
    NO_COPY_OPERATOR(TypeName)

#define NO_MOVE_SEMANTIC(TypeName) \
    NO_MOVE_CTOR(TypeName);        \
    NO_MOVE_OPERATOR(TypeName)

#endif // ENCRYPTION_COMMON_MACROS_H
