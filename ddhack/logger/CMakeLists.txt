project(ddhack_logger)

add_library(ddraw SHARED
    stdafx.cpp
    stdafx.h ddraw.h
    ddwrapper.cpp ddwrapper.h
    myIDDraw.h
    myIDDraw1.cpp
    myIDDraw2.cpp
    myIDDraw4.cpp
    myIDDraw7.cpp
    myIDDrawPalette.cpp
    myIDDrawSurface1.cpp
    myIDDrawSurface2.cpp
    myIDDrawSurface3.cpp
    myIDDrawSurface4.cpp
    myIDDrawSurface7.cpp
)
