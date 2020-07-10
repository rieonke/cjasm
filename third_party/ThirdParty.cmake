include(ExternalProject)

set(THIRD_PARTY_BUILD_DIR ${CMAKE_BINARY_DIR}/third_party)

externalproject_add(
        libcmocka
        URL https://cmocka.org/files/1.1/cmocka-1.1.5.tar.xz
        URL_HASH SHA256=f0ccd8242d55e2fd74b16ba518359151f6f8383ff8aef4976e48393f77bba8b6
        PREFIX ${THIRD_PARTY_BUILD_DIR}
        INSTALL_DIR ${THIRD_PARTY_BUILD_DIR}
        CONFIGURE_COMMAND ${CMAKE_COMMAND} <SOURCE_DIR> -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR> -DBUILD_STATIC_LIB=1
)


include_directories(${THIRD_PARTY_BUILD_DIR}/include)
link_directories(${THIRD_PARTY_BUILD_DIR}/lib)