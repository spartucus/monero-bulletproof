TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

QMAKE_CXXFLAGS += --coverage
QMAKE_LFLAGS += --coverage

SOURCES += \
        common/aligned.c \
        common/perf_timer.cpp \
        crypto/chacha.c \
        crypto/crypto-ops-data.c \
        crypto/crypto-ops.c \
        crypto/crypto.cpp \
        crypto/crypto_ops_builder/verify.c \
        crypto/hash.c \
        crypto/keccak.c \
        crypto/random.c \
        easylogging++/easylogging++.cc \
        epee/memwipe.c \
        epee/mlocker.cpp \
        main.cpp \
        ringct/bulletproofs.cc \
        ringct/multiexp.cc \
        ringct/rctCryptoOps.c \
        ringct/rctOps.cpp

HEADERS += \
    common/aligned.h \
    common/perf_timer.h \
    common/pod-class.h \
    common/varint.h \
    crypto/chacha.h \
    crypto/crypto-ops.h \
    crypto/crypto.h \
    crypto/crypto_ops_builder/crypto_verify_32.h \
    crypto/generic-ops.h \
    crypto/hash-ops.h \
    crypto/hash.h \
    crypto/initializer.h \
    crypto/keccak.h \
    crypto/random.h \
    easylogging++/ea_config.h \
    easylogging++/easylogging++.h \
    epee/fnv1.h \
    epee/int-util.h \
    epee/memwipe.h \
    epee/misc_log_ex.h \
    epee/misc_os_dependent.h \
    epee/mlocker.h \
    epee/span.h \
    epee/storages/parserse_base_utils.h \
    epee/string_tools.h \
    epee/syncobj.h \
    epee/warnings.h \
    ringct/bulletproofs.h \
    ringct/multiexp.h \
    ringct/rctCryptoOps.h \
    ringct/rctOps.h \
    ringct/rctTypes.h \
    serialization/binary_archive.h \
    serialization/container.h \
    serialization/crypto.h \
    serialization/debug_archive.h \
    serialization/json_archive.h \
    serialization/serialization.h \
    serialization/string.h \
    serialization/variant.h \
    serialization/vector.h

INCLUDEPATH += /usr/local/include
INCLUDEPATH += $$PWD/epee
INCLUDEPATH += $$PWD/easylogging++
INCLUDEPATH += $$PWD/crypto

LIBS += -L"/usr/local/lib" -lboost_thread-mt -lboost_chrono
