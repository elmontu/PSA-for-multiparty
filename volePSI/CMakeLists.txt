set(SRCS
    "RsSimpleHashPsi.cpp"
    "fileBased.cpp"
    "MpStarChannel.cpp"
    "MpStarSetup.cpp"
    "MpStarCrypto.cpp"
    "MpSpHandshake.cpp"
    "MpKem.cpp"
    "MpHybridHandshake.cpp"
    "MpTranscript.cpp"
    "MpIdentity.cpp"
    "MpMac.cpp"
    "MpAuthCascade.cpp"
    "MpCgpShuffle.cpp"
    "MpObliviousSort.cpp"
    "MpJoinExpander.cpp"
    "MpJoinFilter.cpp"
    "MpsaJoinDriver.cpp"
    "MpsaJoinDriverWire.cpp"
    "MpSecretShare.cpp"
    "MpBeaverTriple.cpp"
    "MpSecureCompare.cpp"
    "MpMpcArithmetic.cpp"
    "MpMpcSort.cpp"
    "MpMpcJoin.cpp"
    "MpsaJoinMpcDriver.cpp"
    "MpRistretto.cpp"
    "MpPedersen.cpp"
    "MpShuffleNizk.cpp"
    "MpOleTriple.cpp"
    "MpMpcWire.cpp"
    "MpOleAlpha.cpp"
    "MpShuffleNizkBg.cpp"
    "MpMpcWireOps.cpp"
    "MpMpcWireDriver.cpp"
    "MpCgpPreprocess.cpp"
    "MpPedersenVector.cpp"
    "MpShuffleDriver.cpp"
    "MpsaShuffleIntegrity.cpp"
    "MpOira.cpp"
    "MpOiraBudget.cpp"
    "MpsvsLocalPrep.cpp"
    "MpsvsOprf.cpp"
    "MpsvsTopology.cpp"
    "MpsvsAlignment.cpp"
    "MpsvsInclusion.cpp"
    "MpsvsRatioBucket.cpp"
    "MpsvsRank.cpp"
    "MpsvsComposite.cpp"
    "MpsvsPercentiles.cpp"
    "MpsvsSectorAgg.cpp"
    "MpsvsDp.cpp"
    "MpsvsOpen.cpp"
    "MpsvsAudit.cpp"
    "MpsvsInclusionWire.cpp"
    "MpsvsSectorAggWire.cpp"
    "MpsvsOpenWire.cpp"
    "MpsvsRatioBucketWire.cpp"
    "MpsvsDpWire.cpp"
    "MpsvsCoverFirms.cpp"
    "MpsvsKAnonGate.cpp"
    "MpsvsAuthShare.cpp"
    "MpsvsReciprocalVerify.cpp"
    "MpsvsShuffleWire.cpp"
    "MpsvsBitProof.cpp"
    "MpsvsProdHygiene.cpp"
    "MpsvsAuthShareProd.cpp"
    "MpsvsDpProd.cpp"
    "MpsvsAuditPersist.cpp"
    "MpsvsMetrics.cpp"
    "MpsvsConfig.cpp"
    "MpsvsConstTime.cpp"
    "MpsvsKeyStore.cpp"
    "MpsvsSecureChannel.cpp"
    "MpsvsCryptoParams.cpp"
    "MpsvsRankWire.cpp"
    "MpsvsGoldschmidtWire.cpp"
    "MpsvsCompositeWire.cpp"
    "MpsvsPercentilesWire.cpp"
    "MpsvsAlignmentWire.cpp"
    "RsMpsi.cpp"
    "RsMpsiVole.cpp"
    "MpsaDriver.cpp"

    # Vendored upstream ladnir/volepsi (subset used by MPSO). See
    # volePSI/upstream/README.md for provenance and integration notes.
    "upstream/volepsi/RsPsi.cpp"
    "upstream/volepsi/RsOprf.cpp"
    "upstream/volepsi/SimpleIndex.cpp"
    "upstream/volepsi/GMW/Circuit.cpp"
    "upstream/volepsi/GMW/Gmw.cpp"
    "upstream/volepsi/GMW/SilentTripleGen.cpp"

    # Vendored real-world-cryptography/MPSO (Dong et al. CCS'25).
    "upstream/mpso/common/permute.cpp"
    "upstream/mpso/mpso/MPSI.cpp"
    "upstream/mpso/mpso/MPSIC.cpp"
    "upstream/mpso/mpso/MPSICS.cpp"
    "upstream/mpso/mpso/MPSU.cpp"
    "upstream/mpso/mpso/PMT.cpp"
    "upstream/mpso/mpso/ROT.cpp"
    "upstream/mpso/offlineGen/BeaverTriplesGen.cpp"
    "upstream/mpso/offlineGen/BoolTriplesGen.cpp"
    "upstream/mpso/offlineGen/PreGen.cpp"
    "upstream/mpso/offlineGen/RotGen.cpp"
    "upstream/mpso/offlineGen/VoleGen.cpp"
    "upstream/mpso/shuffle/MShuffle.cpp"
    "upstream/mpso/shuffle/ShareCorrelationGen.cpp"
    )


set(MY_LIBS libOTe cryptoTools relic_s)

include_directories(out/install/${PRESET_NAME}/include)
include_directories(out/libOTe/cryptoTools/thirdparty/${OS}/include/)

link_directories(out/install/${PRESET_NAME}/lib)

list(APPEND SRCS
        "osn/benes.cpp"
        "osn/benes.h"
        "osn/OSNReceiver.cpp"
        "osn/OSNReceiver.h"
        "osn/OSNSender.cpp"
        "osn/OSNSender.h")
        
add_library(volePSI STATIC ${SRCS})

# libsodium (X25519 in MpStarSetup). find_package via PkgConfig keeps CMake
# free of system-path assumptions.
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)
target_include_directories(volePSI PRIVATE ${SODIUM_INCLUDE_DIRS})

target_link_libraries(volePSI oc::libOTe sparsehash libdivide ${SODIUM_LIBRARIES})

if(APPLE)
    target_compile_options(volePSI PRIVATE
        "-std=c++${VOLE_PSI_STD_VER}"
    )    
    target_compile_options(volePSI PRIVATE
        "-Wno-pessimizing-move"
        "-Wno-delete-non-abstract-non-virtual-dtor"
    )
elseif(MSVC)
    set_target_properties(volePSI
        PROPERTIES
            CXX_STANDARD ${VOLE_PSI_STD_VER}
            CXX_STANDARD_REQUIRED YES
            CXX_EXTENSIONS NO
    )

    if(VOLE_PSI_ENABLE_ASAN)
        message(WARNING "volepsi has ASAN enabled")
        target_compile_options(volePSI PUBLIC "/fsanitize=address")
        target_link_options(volePSI PUBLIC "/fsanitize=address")

    endif()
else()
    target_compile_options(volePSI PUBLIC
        "-std=c++${VOLE_PSI_STD_VER}"
    )    

    if(VOLE_PSI_ENABLE_ASAN)
        message(WARNING "volepsi has ASAN enabled")
        target_compile_options(volePSI PUBLIC "-fsanitize=address")# "-ftime-report")
        target_link_options(volePSI PUBLIC "-fsanitize=address")
    endif()
endif()

if(MSVC)
    target_compile_definitions(volePSI PUBLIC "_ENABLE_EXTENDED_ALIGNED_STORAGE")
else()

    if(VOLE_PSI_ENABLE_SSE)
        target_compile_options(volePSI PUBLIC -mavx)
    endif()

    if(VOLE_PSI_ENABLE_PIC)
        target_compile_options(volePSI PUBLIC "-fPIC")
    endif()
endif()

#target_compile_features(volePSI PUBLIC cxx_std_17)
# make projects that include volePSI use this as an include folder
target_include_directories(volePSI PUBLIC 
                    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/..>
                    $<INSTALL_INTERFACE:include>) 
target_include_directories(volePSI PUBLIC 
                    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/..>
                    $<INSTALL_INTERFACE:include>) 

