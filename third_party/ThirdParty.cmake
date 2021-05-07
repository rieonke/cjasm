include(ExternalProject)

set(THIRD_PARTY_BUILD_DIR ${CMAKE_BINARY_DIR}/third_party)

externalproject_add(
        libcmocka
        URL https://gitlab.com/cmocka/cmocka/-/archive/cmocka-1.1.5/cmocka-cmocka-1.1.5.tar.gz
        URL_HASH SHA256=51eba78277d51f0299617bedffc388b2b4ea478f5cc9876cc2544dae79638cb0
        PREFIX ${THIRD_PARTY_BUILD_DIR}
        INSTALL_DIR ${THIRD_PARTY_BUILD_DIR}
        CONFIGURE_COMMAND ${CMAKE_COMMAND} <SOURCE_DIR> -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR> -DBUILD_STATIC_LIB=1
)


include_directories(${THIRD_PARTY_BUILD_DIR}/include)
link_directories(${THIRD_PARTY_BUILD_DIR}/lib)