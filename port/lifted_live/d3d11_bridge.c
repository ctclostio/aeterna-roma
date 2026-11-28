/*
 * d3d11_bridge.c - Direct3D 11, DXGI and D3DCompiler for a 32-bit guest on a
 * 64-bit host. d3d11_bridge.h describes the model.
 *
 *   1. interface tables: vtable order and argument counts, generated from the SDK headers
 *   2. 32-bit layouts of the structures that differ between x86 and x64, with proofs
 *   3. guest objects: the table pairing a guest object with a host interface pointer
 *   4. argument conversion
 *   5. one function per vtable slot, grouped by interface
 *   6. development aids (a record of the calls, Direct3D's debug layer) and the exported entry points
 *   7. the glue for live_main.c (only with D3D11_BRIDGE_LIVE)
 *
 * Every slot of every bridged interface has a function. The ones that cannot
 * be done faithfully stop the run and name themselves (search for B11_UNSUP
 * and for b11_host.stop): storing a guest IUnknown on a host object,
 * IDXGISurface, software adapters, and the methods of D3DCompiler_42's shader
 * reflection interface that the game does not call.
 *
 * The guest never reaches an m_ function directly: the vtables hold the b11_w_
 * wrappers, and the exported entry points are wrappers too. That is where the
 * development aids of section 6 see every call.
 *
 * Locks. b11_lock guards the object table and nothing else is done under it:
 * no host COM call (the host calls back into b11_note_Release from inside its
 * own locks) and no host callback (the runner has locks of its own).
 *
 * The file compiles on its own or included into live_main.c, which is the one
 * source live.exe is built from. Every name at file scope therefore starts with
 * b11_, B11_, m_<interface>_, K_<interface>, g32_ or d3d11_bridge_.
 */
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS /* getenv, fopen */
#endif
#ifndef COBJMACROS
#define COBJMACROS
#endif
#ifndef CINTERFACE
#define CINTERFACE
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <initguid.h> /* the IID_ constants of the headers below are defined in this file */

#pragma warning(push)
#pragma warning(disable : 4201) /* nameless unions in the Direct3D headers */
#include <d3d11.h>
#include <d3dcompiler.h>
#include <dxgi.h>
#include <dxgidebug.h>
#pragma warning(pop)

#undef INITGUID
#include <guiddef.h> /* DEFINE_GUID declares again, for whatever follows this file */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "d3d11_bridge.h"

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "d3dcompiler.lib") /* imports d3dcompiler_47.dll */
#pragma comment(lib, "uuid.lib")

/* ---- 1. interface tables ----------------------------------------------------------------------- */

/* ---- BEGIN GENERATED (scripts/lift/gen_d3d11_bridge.py) ---- */
/* From the Windows SDK 10.0.26100.0 headers. Do not edit: rerun the script.
 * I(interface, parent); the root is its own parent.
 * M(interface, declaring interface, method, vtable slot, x86 stack dwords including This, return class):
 *   V void, D dword, Z SIZE_T, P host pointer, F float in x87 st(0).
 * D(interface, method, vtable slot, x86 stack dwords, return class, arguments): the methods an interface
 *   declares itself, which is the name a method is registered under. One letter for each argument dword:
 *   t This, v value, h handle, g pointer to a GUID, s string, i interface pointer, o pointer to pointers,
 *   p other pointer.
 * E(import DLL, export, x86 stack dwords, arguments). */
#define B11_IFACES(I) \
    I(IUnknown, IUnknown) \
    I(IDXGIObject, IUnknown) \
    I(IDXGIDeviceSubObject, IDXGIObject) \
    I(IDXGIFactory, IDXGIObject) \
    I(IDXGIFactory1, IDXGIFactory) \
    I(IDXGIAdapter, IDXGIObject) \
    I(IDXGIAdapter1, IDXGIAdapter) \
    I(IDXGIOutput, IDXGIObject) \
    I(IDXGISwapChain, IDXGIDeviceSubObject) \
    I(IDXGIDevice, IDXGIObject) \
    I(IDXGIDevice1, IDXGIDevice) \
    I(ID3D10Blob, IUnknown) \
    I(ID3D11DeviceChild, IUnknown) \
    I(ID3D11Resource, ID3D11DeviceChild) \
    I(ID3D11Buffer, ID3D11Resource) \
    I(ID3D11Texture1D, ID3D11Resource) \
    I(ID3D11Texture2D, ID3D11Resource) \
    I(ID3D11Texture3D, ID3D11Resource) \
    I(ID3D11View, ID3D11DeviceChild) \
    I(ID3D11RenderTargetView, ID3D11View) \
    I(ID3D11DepthStencilView, ID3D11View) \
    I(ID3D11ShaderResourceView, ID3D11View) \
    I(ID3D11UnorderedAccessView, ID3D11View) \
    I(ID3D11InputLayout, ID3D11DeviceChild) \
    I(ID3D11VertexShader, ID3D11DeviceChild) \
    I(ID3D11PixelShader, ID3D11DeviceChild) \
    I(ID3D11GeometryShader, ID3D11DeviceChild) \
    I(ID3D11HullShader, ID3D11DeviceChild) \
    I(ID3D11DomainShader, ID3D11DeviceChild) \
    I(ID3D11ComputeShader, ID3D11DeviceChild) \
    I(ID3D11SamplerState, ID3D11DeviceChild) \
    I(ID3D11RasterizerState, ID3D11DeviceChild) \
    I(ID3D11BlendState, ID3D11DeviceChild) \
    I(ID3D11DepthStencilState, ID3D11DeviceChild) \
    I(ID3D11Asynchronous, ID3D11DeviceChild) \
    I(ID3D11Query, ID3D11Asynchronous) \
    I(ID3D11Predicate, ID3D11Query) \
    I(ID3D11Counter, ID3D11Asynchronous) \
    I(ID3D11ClassInstance, ID3D11DeviceChild) \
    I(ID3D11ClassLinkage, ID3D11DeviceChild) \
    I(ID3D11CommandList, ID3D11DeviceChild) \
    I(ID3D11DeviceContext, ID3D11DeviceChild) \
    I(ID3D11Device, IUnknown)
#define B11_METHODS_IUnknown(M) \
    M(IUnknown, IUnknown, QueryInterface, 0, 3, 'D') \
    M(IUnknown, IUnknown, AddRef, 1, 1, 'D') \
    M(IUnknown, IUnknown, Release, 2, 1, 'D')
#define B11_METHODS_IDXGIObject(M) \
    M(IDXGIObject, IUnknown, QueryInterface, 0, 3, 'D') \
    M(IDXGIObject, IUnknown, AddRef, 1, 1, 'D') \
    M(IDXGIObject, IUnknown, Release, 2, 1, 'D') \
    M(IDXGIObject, IDXGIObject, SetPrivateData, 3, 4, 'D') \
    M(IDXGIObject, IDXGIObject, SetPrivateDataInterface, 4, 3, 'D') \
    M(IDXGIObject, IDXGIObject, GetPrivateData, 5, 4, 'D') \
    M(IDXGIObject, IDXGIObject, GetParent, 6, 3, 'D')
#define B11_METHODS_IDXGIDeviceSubObject(M) \
    M(IDXGIDeviceSubObject, IUnknown, QueryInterface, 0, 3, 'D') \
    M(IDXGIDeviceSubObject, IUnknown, AddRef, 1, 1, 'D') \
    M(IDXGIDeviceSubObject, IUnknown, Release, 2, 1, 'D') \
    M(IDXGIDeviceSubObject, IDXGIObject, SetPrivateData, 3, 4, 'D') \
    M(IDXGIDeviceSubObject, IDXGIObject, SetPrivateDataInterface, 4, 3, 'D') \
    M(IDXGIDeviceSubObject, IDXGIObject, GetPrivateData, 5, 4, 'D') \
    M(IDXGIDeviceSubObject, IDXGIObject, GetParent, 6, 3, 'D') \
    M(IDXGIDeviceSubObject, IDXGIDeviceSubObject, GetDevice, 7, 3, 'D')
#define B11_METHODS_IDXGIFactory(M) \
    M(IDXGIFactory, IUnknown, QueryInterface, 0, 3, 'D') \
    M(IDXGIFactory, IUnknown, AddRef, 1, 1, 'D') \
    M(IDXGIFactory, IUnknown, Release, 2, 1, 'D') \
    M(IDXGIFactory, IDXGIObject, SetPrivateData, 3, 4, 'D') \
    M(IDXGIFactory, IDXGIObject, SetPrivateDataInterface, 4, 3, 'D') \
    M(IDXGIFactory, IDXGIObject, GetPrivateData, 5, 4, 'D') \
    M(IDXGIFactory, IDXGIObject, GetParent, 6, 3, 'D') \
    M(IDXGIFactory, IDXGIFactory, EnumAdapters, 7, 3, 'D') \
    M(IDXGIFactory, IDXGIFactory, MakeWindowAssociation, 8, 3, 'D') \
    M(IDXGIFactory, IDXGIFactory, GetWindowAssociation, 9, 2, 'D') \
    M(IDXGIFactory, IDXGIFactory, CreateSwapChain, 10, 4, 'D') \
    M(IDXGIFactory, IDXGIFactory, CreateSoftwareAdapter, 11, 3, 'D')
#define B11_METHODS_IDXGIFactory1(M) \
    M(IDXGIFactory1, IUnknown, QueryInterface, 0, 3, 'D') \
    M(IDXGIFactory1, IUnknown, AddRef, 1, 1, 'D') \
    M(IDXGIFactory1, IUnknown, Release, 2, 1, 'D') \
    M(IDXGIFactory1, IDXGIObject, SetPrivateData, 3, 4, 'D') \
    M(IDXGIFactory1, IDXGIObject, SetPrivateDataInterface, 4, 3, 'D') \
    M(IDXGIFactory1, IDXGIObject, GetPrivateData, 5, 4, 'D') \
    M(IDXGIFactory1, IDXGIObject, GetParent, 6, 3, 'D') \
    M(IDXGIFactory1, IDXGIFactory, EnumAdapters, 7, 3, 'D') \
    M(IDXGIFactory1, IDXGIFactory, MakeWindowAssociation, 8, 3, 'D') \
    M(IDXGIFactory1, IDXGIFactory, GetWindowAssociation, 9, 2, 'D') \
    M(IDXGIFactory1, IDXGIFactory, CreateSwapChain, 10, 4, 'D') \
    M(IDXGIFactory1, IDXGIFactory, CreateSoftwareAdapter, 11, 3, 'D') \
    M(IDXGIFactory1, IDXGIFactory1, EnumAdapters1, 12, 3, 'D') \
    M(IDXGIFactory1, IDXGIFactory1, IsCurrent, 13, 1, 'D')
#define B11_METHODS_IDXGIAdapter(M) \
    M(IDXGIAdapter, IUnknown, QueryInterface, 0, 3, 'D') \
    M(IDXGIAdapter, IUnknown, AddRef, 1, 1, 'D') \
    M(IDXGIAdapter, IUnknown, Release, 2, 1, 'D') \
    M(IDXGIAdapter, IDXGIObject, SetPrivateData, 3, 4, 'D') \
    M(IDXGIAdapter, IDXGIObject, SetPrivateDataInterface, 4, 3, 'D') \
    M(IDXGIAdapter, IDXGIObject, GetPrivateData, 5, 4, 'D') \
    M(IDXGIAdapter, IDXGIObject, GetParent, 6, 3, 'D') \
    M(IDXGIAdapter, IDXGIAdapter, EnumOutputs, 7, 3, 'D') \
    M(IDXGIAdapter, IDXGIAdapter, GetDesc, 8, 2, 'D') \
    M(IDXGIAdapter, IDXGIAdapter, CheckInterfaceSupport, 9, 3, 'D')
#define B11_METHODS_IDXGIAdapter1(M) \
    M(IDXGIAdapter1, IUnknown, QueryInterface, 0, 3, 'D') \
    M(IDXGIAdapter1, IUnknown, AddRef, 1, 1, 'D') \
    M(IDXGIAdapter1, IUnknown, Release, 2, 1, 'D') \
    M(IDXGIAdapter1, IDXGIObject, SetPrivateData, 3, 4, 'D') \
    M(IDXGIAdapter1, IDXGIObject, SetPrivateDataInterface, 4, 3, 'D') \
    M(IDXGIAdapter1, IDXGIObject, GetPrivateData, 5, 4, 'D') \
    M(IDXGIAdapter1, IDXGIObject, GetParent, 6, 3, 'D') \
    M(IDXGIAdapter1, IDXGIAdapter, EnumOutputs, 7, 3, 'D') \
    M(IDXGIAdapter1, IDXGIAdapter, GetDesc, 8, 2, 'D') \
    M(IDXGIAdapter1, IDXGIAdapter, CheckInterfaceSupport, 9, 3, 'D') \
    M(IDXGIAdapter1, IDXGIAdapter1, GetDesc1, 10, 2, 'D')
#define B11_METHODS_IDXGIOutput(M) \
    M(IDXGIOutput, IUnknown, QueryInterface, 0, 3, 'D') \
    M(IDXGIOutput, IUnknown, AddRef, 1, 1, 'D') \
    M(IDXGIOutput, IUnknown, Release, 2, 1, 'D') \
    M(IDXGIOutput, IDXGIObject, SetPrivateData, 3, 4, 'D') \
    M(IDXGIOutput, IDXGIObject, SetPrivateDataInterface, 4, 3, 'D') \
    M(IDXGIOutput, IDXGIObject, GetPrivateData, 5, 4, 'D') \
    M(IDXGIOutput, IDXGIObject, GetParent, 6, 3, 'D') \
    M(IDXGIOutput, IDXGIOutput, GetDesc, 7, 2, 'D') \
    M(IDXGIOutput, IDXGIOutput, GetDisplayModeList, 8, 5, 'D') \
    M(IDXGIOutput, IDXGIOutput, FindClosestMatchingMode, 9, 4, 'D') \
    M(IDXGIOutput, IDXGIOutput, WaitForVBlank, 10, 1, 'D') \
    M(IDXGIOutput, IDXGIOutput, TakeOwnership, 11, 3, 'D') \
    M(IDXGIOutput, IDXGIOutput, ReleaseOwnership, 12, 1, 'V') \
    M(IDXGIOutput, IDXGIOutput, GetGammaControlCapabilities, 13, 2, 'D') \
    M(IDXGIOutput, IDXGIOutput, SetGammaControl, 14, 2, 'D') \
    M(IDXGIOutput, IDXGIOutput, GetGammaControl, 15, 2, 'D') \
    M(IDXGIOutput, IDXGIOutput, SetDisplaySurface, 16, 2, 'D') \
    M(IDXGIOutput, IDXGIOutput, GetDisplaySurfaceData, 17, 2, 'D') \
    M(IDXGIOutput, IDXGIOutput, GetFrameStatistics, 18, 2, 'D')
#define B11_METHODS_IDXGISwapChain(M) \
    M(IDXGISwapChain, IUnknown, QueryInterface, 0, 3, 'D') \
    M(IDXGISwapChain, IUnknown, AddRef, 1, 1, 'D') \
    M(IDXGISwapChain, IUnknown, Release, 2, 1, 'D') \
    M(IDXGISwapChain, IDXGIObject, SetPrivateData, 3, 4, 'D') \
    M(IDXGISwapChain, IDXGIObject, SetPrivateDataInterface, 4, 3, 'D') \
    M(IDXGISwapChain, IDXGIObject, GetPrivateData, 5, 4, 'D') \
    M(IDXGISwapChain, IDXGIObject, GetParent, 6, 3, 'D') \
    M(IDXGISwapChain, IDXGIDeviceSubObject, GetDevice, 7, 3, 'D') \
    M(IDXGISwapChain, IDXGISwapChain, Present, 8, 3, 'D') \
    M(IDXGISwapChain, IDXGISwapChain, GetBuffer, 9, 4, 'D') \
    M(IDXGISwapChain, IDXGISwapChain, SetFullscreenState, 10, 3, 'D') \
    M(IDXGISwapChain, IDXGISwapChain, GetFullscreenState, 11, 3, 'D') \
    M(IDXGISwapChain, IDXGISwapChain, GetDesc, 12, 2, 'D') \
    M(IDXGISwapChain, IDXGISwapChain, ResizeBuffers, 13, 6, 'D') \
    M(IDXGISwapChain, IDXGISwapChain, ResizeTarget, 14, 2, 'D') \
    M(IDXGISwapChain, IDXGISwapChain, GetContainingOutput, 15, 2, 'D') \
    M(IDXGISwapChain, IDXGISwapChain, GetFrameStatistics, 16, 2, 'D') \
    M(IDXGISwapChain, IDXGISwapChain, GetLastPresentCount, 17, 2, 'D')
#define B11_METHODS_IDXGIDevice(M) \
    M(IDXGIDevice, IUnknown, QueryInterface, 0, 3, 'D') \
    M(IDXGIDevice, IUnknown, AddRef, 1, 1, 'D') \
    M(IDXGIDevice, IUnknown, Release, 2, 1, 'D') \
    M(IDXGIDevice, IDXGIObject, SetPrivateData, 3, 4, 'D') \
    M(IDXGIDevice, IDXGIObject, SetPrivateDataInterface, 4, 3, 'D') \
    M(IDXGIDevice, IDXGIObject, GetPrivateData, 5, 4, 'D') \
    M(IDXGIDevice, IDXGIObject, GetParent, 6, 3, 'D') \
    M(IDXGIDevice, IDXGIDevice, GetAdapter, 7, 2, 'D') \
    M(IDXGIDevice, IDXGIDevice, CreateSurface, 8, 6, 'D') \
    M(IDXGIDevice, IDXGIDevice, QueryResourceResidency, 9, 4, 'D') \
    M(IDXGIDevice, IDXGIDevice, SetGPUThreadPriority, 10, 2, 'D') \
    M(IDXGIDevice, IDXGIDevice, GetGPUThreadPriority, 11, 2, 'D')
#define B11_METHODS_IDXGIDevice1(M) \
    M(IDXGIDevice1, IUnknown, QueryInterface, 0, 3, 'D') \
    M(IDXGIDevice1, IUnknown, AddRef, 1, 1, 'D') \
    M(IDXGIDevice1, IUnknown, Release, 2, 1, 'D') \
    M(IDXGIDevice1, IDXGIObject, SetPrivateData, 3, 4, 'D') \
    M(IDXGIDevice1, IDXGIObject, SetPrivateDataInterface, 4, 3, 'D') \
    M(IDXGIDevice1, IDXGIObject, GetPrivateData, 5, 4, 'D') \
    M(IDXGIDevice1, IDXGIObject, GetParent, 6, 3, 'D') \
    M(IDXGIDevice1, IDXGIDevice, GetAdapter, 7, 2, 'D') \
    M(IDXGIDevice1, IDXGIDevice, CreateSurface, 8, 6, 'D') \
    M(IDXGIDevice1, IDXGIDevice, QueryResourceResidency, 9, 4, 'D') \
    M(IDXGIDevice1, IDXGIDevice, SetGPUThreadPriority, 10, 2, 'D') \
    M(IDXGIDevice1, IDXGIDevice, GetGPUThreadPriority, 11, 2, 'D') \
    M(IDXGIDevice1, IDXGIDevice1, SetMaximumFrameLatency, 12, 2, 'D') \
    M(IDXGIDevice1, IDXGIDevice1, GetMaximumFrameLatency, 13, 2, 'D')
#define B11_METHODS_ID3D10Blob(M) \
    M(ID3D10Blob, IUnknown, QueryInterface, 0, 3, 'D') \
    M(ID3D10Blob, IUnknown, AddRef, 1, 1, 'D') \
    M(ID3D10Blob, IUnknown, Release, 2, 1, 'D') \
    M(ID3D10Blob, ID3D10Blob, GetBufferPointer, 3, 1, 'P') \
    M(ID3D10Blob, ID3D10Blob, GetBufferSize, 4, 1, 'Z')
#define B11_METHODS_ID3D11DeviceChild(M) \
    M(ID3D11DeviceChild, IUnknown, QueryInterface, 0, 3, 'D') \
    M(ID3D11DeviceChild, IUnknown, AddRef, 1, 1, 'D') \
    M(ID3D11DeviceChild, IUnknown, Release, 2, 1, 'D') \
    M(ID3D11DeviceChild, ID3D11DeviceChild, GetDevice, 3, 2, 'V') \
    M(ID3D11DeviceChild, ID3D11DeviceChild, GetPrivateData, 4, 4, 'D') \
    M(ID3D11DeviceChild, ID3D11DeviceChild, SetPrivateData, 5, 4, 'D') \
    M(ID3D11DeviceChild, ID3D11DeviceChild, SetPrivateDataInterface, 6, 3, 'D')
#define B11_METHODS_ID3D11Resource(M) \
    M(ID3D11Resource, IUnknown, QueryInterface, 0, 3, 'D') \
    M(ID3D11Resource, IUnknown, AddRef, 1, 1, 'D') \
    M(ID3D11Resource, IUnknown, Release, 2, 1, 'D') \
    M(ID3D11Resource, ID3D11DeviceChild, GetDevice, 3, 2, 'V') \
    M(ID3D11Resource, ID3D11DeviceChild, GetPrivateData, 4, 4, 'D') \
    M(ID3D11Resource, ID3D11DeviceChild, SetPrivateData, 5, 4, 'D') \
    M(ID3D11Resource, ID3D11DeviceChild, SetPrivateDataInterface, 6, 3, 'D') \
    M(ID3D11Resource, ID3D11Resource, GetType, 7, 2, 'V') \
    M(ID3D11Resource, ID3D11Resource, SetEvictionPriority, 8, 2, 'V') \
    M(ID3D11Resource, ID3D11Resource, GetEvictionPriority, 9, 1, 'D')
#define B11_METHODS_ID3D11Buffer(M) \
    M(ID3D11Buffer, IUnknown, QueryInterface, 0, 3, 'D') \
    M(ID3D11Buffer, IUnknown, AddRef, 1, 1, 'D') \
    M(ID3D11Buffer, IUnknown, Release, 2, 1, 'D') \
    M(ID3D11Buffer, ID3D11DeviceChild, GetDevice, 3, 2, 'V') \
    M(ID3D11Buffer, ID3D11DeviceChild, GetPrivateData, 4, 4, 'D') \
    M(ID3D11Buffer, ID3D11DeviceChild, SetPrivateData, 5, 4, 'D') \
    M(ID3D11Buffer, ID3D11DeviceChild, SetPrivateDataInterface, 6, 3, 'D') \
    M(ID3D11Buffer, ID3D11Resource, GetType, 7, 2, 'V') \
    M(ID3D11Buffer, ID3D11Resource, SetEvictionPriority, 8, 2, 'V') \
    M(ID3D11Buffer, ID3D11Resource, GetEvictionPriority, 9, 1, 'D') \
    M(ID3D11Buffer, ID3D11Buffer, GetDesc, 10, 2, 'V')
#define B11_METHODS_ID3D11Texture1D(M) \
    M(ID3D11Texture1D, IUnknown, QueryInterface, 0, 3, 'D') \
    M(ID3D11Texture1D, IUnknown, AddRef, 1, 1, 'D') \
    M(ID3D11Texture1D, IUnknown, Release, 2, 1, 'D') \
    M(ID3D11Texture1D, ID3D11DeviceChild, GetDevice, 3, 2, 'V') \
    M(ID3D11Texture1D, ID3D11DeviceChild, GetPrivateData, 4, 4, 'D') \
    M(ID3D11Texture1D, ID3D11DeviceChild, SetPrivateData, 5, 4, 'D') \
    M(ID3D11Texture1D, ID3D11DeviceChild, SetPrivateDataInterface, 6, 3, 'D') \
    M(ID3D11Texture1D, ID3D11Resource, GetType, 7, 2, 'V') \
    M(ID3D11Texture1D, ID3D11Resource, SetEvictionPriority, 8, 2, 'V') \
    M(ID3D11Texture1D, ID3D11Resource, GetEvictionPriority, 9, 1, 'D') \
    M(ID3D11Texture1D, ID3D11Texture1D, GetDesc, 10, 2, 'V')
#define B11_METHODS_ID3D11Texture2D(M) \
    M(ID3D11Texture2D, IUnknown, QueryInterface, 0, 3, 'D') \
    M(ID3D11Texture2D, IUnknown, AddRef, 1, 1, 'D') \
    M(ID3D11Texture2D, IUnknown, Release, 2, 1, 'D') \
    M(ID3D11Texture2D, ID3D11DeviceChild, GetDevice, 3, 2, 'V') \
    M(ID3D11Texture2D, ID3D11DeviceChild, GetPrivateData, 4, 4, 'D') \
    M(ID3D11Texture2D, ID3D11DeviceChild, SetPrivateData, 5, 4, 'D') \
    M(ID3D11Texture2D, ID3D11DeviceChild, SetPrivateDataInterface, 6, 3, 'D') \
    M(ID3D11Texture2D, ID3D11Resource, GetType, 7, 2, 'V') \
    M(ID3D11Texture2D, ID3D11Resource, SetEvictionPriority, 8, 2, 'V') \
    M(ID3D11Texture2D, ID3D11Resource, GetEvictionPriority, 9, 1, 'D') \
    M(ID3D11Texture2D, ID3D11Texture2D, GetDesc, 10, 2, 'V')
#define B11_METHODS_ID3D11Texture3D(M) \
    M(ID3D11Texture3D, IUnknown, QueryInterface, 0, 3, 'D') \
    M(ID3D11Texture3D, IUnknown, AddRef, 1, 1, 'D') \
    M(ID3D11Texture3D, IUnknown, Release, 2, 1, 'D') \
    M(ID3D11Texture3D, ID3D11DeviceChild, GetDevice, 3, 2, 'V') \
    M(ID3D11Texture3D, ID3D11DeviceChild, GetPrivateData, 4, 4, 'D') \
    M(ID3D11Texture3D, ID3D11DeviceChild, SetPrivateData, 5, 4, 'D') \
    M(ID3D11Texture3D, ID3D11DeviceChild, SetPrivateDataInterface, 6, 3, 'D') \
    M(ID3D11Texture3D, ID3D11Resource, GetType, 7, 2, 'V') \
    M(ID3D11Texture3D, ID3D11Resource, SetEvictionPriority, 8, 2, 'V') \
    M(ID3D11Texture3D, ID3D11Resource, GetEvictionPriority, 9, 1, 'D') \
    M(ID3D11Texture3D, ID3D11Texture3D, GetDesc, 10, 2, 'V')
#define B11_METHODS_ID3D11View(M) \
    M(ID3D11View, IUnknown, QueryInterface, 0, 3, 'D') \
    M(ID3D11View, IUnknown, AddRef, 1, 1, 'D') \
    M(ID3D11View, IUnknown, Release, 2, 1, 'D') \
    M(ID3D11View, ID3D11DeviceChild, GetDevice, 3, 2, 'V') \
    M(ID3D11View, ID3D11DeviceChild, GetPrivateData, 4, 4, 'D') \
    M(ID3D11View, ID3D11DeviceChild, SetPrivateData, 5, 4, 'D') \
    M(ID3D11View, ID3D11DeviceChild, SetPrivateDataInterface, 6, 3, 'D') \
    M(ID3D11View, ID3D11View, GetResource, 7, 2, 'V')
#define B11_METHODS_ID3D11RenderTargetView(M) \
    M(ID3D11RenderTargetView, IUnknown, QueryInterface, 0, 3, 'D') \
    M(ID3D11RenderTargetView, IUnknown, AddRef, 1, 1, 'D') \
    M(ID3D11RenderTargetView, IUnknown, Release, 2, 1, 'D') \
    M(ID3D11RenderTargetView, ID3D11DeviceChild, GetDevice, 3, 2, 'V') \
    M(ID3D11RenderTargetView, ID3D11DeviceChild, GetPrivateData, 4, 4, 'D') \
    M(ID3D11RenderTargetView, ID3D11DeviceChild, SetPrivateData, 5, 4, 'D') \
    M(ID3D11RenderTargetView, ID3D11DeviceChild, SetPrivateDataInterface, 6, 3, 'D') \
    M(ID3D11RenderTargetView, ID3D11View, GetResource, 7, 2, 'V') \
    M(ID3D11RenderTargetView, ID3D11RenderTargetView, GetDesc, 8, 2, 'V')
#define B11_METHODS_ID3D11DepthStencilView(M) \
    M(ID3D11DepthStencilView, IUnknown, QueryInterface, 0, 3, 'D') \
    M(ID3D11DepthStencilView, IUnknown, AddRef, 1, 1, 'D') \
    M(ID3D11DepthStencilView, IUnknown, Release, 2, 1, 'D') \
    M(ID3D11DepthStencilView, ID3D11DeviceChild, GetDevice, 3, 2, 'V') \
    M(ID3D11DepthStencilView, ID3D11DeviceChild, GetPrivateData, 4, 4, 'D') \
    M(ID3D11DepthStencilView, ID3D11DeviceChild, SetPrivateData, 5, 4, 'D') \
    M(ID3D11DepthStencilView, ID3D11DeviceChild, SetPrivateDataInterface, 6, 3, 'D') \
    M(ID3D11DepthStencilView, ID3D11View, GetResource, 7, 2, 'V') \
    M(ID3D11DepthStencilView, ID3D11DepthStencilView, GetDesc, 8, 2, 'V')
#define B11_METHODS_ID3D11ShaderResourceView(M) \
    M(ID3D11ShaderResourceView, IUnknown, QueryInterface, 0, 3, 'D') \
    M(ID3D11ShaderResourceView, IUnknown, AddRef, 1, 1, 'D') \
    M(ID3D11ShaderResourceView, IUnknown, Release, 2, 1, 'D') \
    M(ID3D11ShaderResourceView, ID3D11DeviceChild, GetDevice, 3, 2, 'V') \
    M(ID3D11ShaderResourceView, ID3D11DeviceChild, GetPrivateData, 4, 4, 'D') \
    M(ID3D11ShaderResourceView, ID3D11DeviceChild, SetPrivateData, 5, 4, 'D') \
    M(ID3D11ShaderResourceView, ID3D11DeviceChild, SetPrivateDataInterface, 6, 3, 'D') \
    M(ID3D11ShaderResourceView, ID3D11View, GetResource, 7, 2, 'V') \
    M(ID3D11ShaderResourceView, ID3D11ShaderResourceView, GetDesc, 8, 2, 'V')
#define B11_METHODS_ID3D11UnorderedAccessView(M) \
    M(ID3D11UnorderedAccessView, IUnknown, QueryInterface, 0, 3, 'D') \
    M(ID3D11UnorderedAccessView, IUnknown, AddRef, 1, 1, 'D') \
    M(ID3D11UnorderedAccessView, IUnknown, Release, 2, 1, 'D') \
    M(ID3D11UnorderedAccessView, ID3D11DeviceChild, GetDevice, 3, 2, 'V') \
    M(ID3D11UnorderedAccessView, ID3D11DeviceChild, GetPrivateData, 4, 4, 'D') \
    M(ID3D11UnorderedAccessView, ID3D11DeviceChild, SetPrivateData, 5, 4, 'D') \
    M(ID3D11UnorderedAccessView, ID3D11DeviceChild, SetPrivateDataInterface, 6, 3, 'D') \
    M(ID3D11UnorderedAccessView, ID3D11View, GetResource, 7, 2, 'V') \
    M(ID3D11UnorderedAccessView, ID3D11UnorderedAccessView, GetDesc, 8, 2, 'V')
#define B11_METHODS_ID3D11InputLayout(M) \
    M(ID3D11InputLayout, IUnknown, QueryInterface, 0, 3, 'D') \
    M(ID3D11InputLayout, IUnknown, AddRef, 1, 1, 'D') \
    M(ID3D11InputLayout, IUnknown, Release, 2, 1, 'D') \
    M(ID3D11InputLayout, ID3D11DeviceChild, GetDevice, 3, 2, 'V') \
    M(ID3D11InputLayout, ID3D11DeviceChild, GetPrivateData, 4, 4, 'D') \
    M(ID3D11InputLayout, ID3D11DeviceChild, SetPrivateData, 5, 4, 'D') \
    M(ID3D11InputLayout, ID3D11DeviceChild, SetPrivateDataInterface, 6, 3, 'D')
#define B11_METHODS_ID3D11VertexShader(M) \
    M(ID3D11VertexShader, IUnknown, QueryInterface, 0, 3, 'D') \
    M(ID3D11VertexShader, IUnknown, AddRef, 1, 1, 'D') \
    M(ID3D11VertexShader, IUnknown, Release, 2, 1, 'D') \
    M(ID3D11VertexShader, ID3D11DeviceChild, GetDevice, 3, 2, 'V') \
    M(ID3D11VertexShader, ID3D11DeviceChild, GetPrivateData, 4, 4, 'D') \
    M(ID3D11VertexShader, ID3D11DeviceChild, SetPrivateData, 5, 4, 'D') \
    M(ID3D11VertexShader, ID3D11DeviceChild, SetPrivateDataInterface, 6, 3, 'D')
#define B11_METHODS_ID3D11PixelShader(M) \
    M(ID3D11PixelShader, IUnknown, QueryInterface, 0, 3, 'D') \
    M(ID3D11PixelShader, IUnknown, AddRef, 1, 1, 'D') \
    M(ID3D11PixelShader, IUnknown, Release, 2, 1, 'D') \
    M(ID3D11PixelShader, ID3D11DeviceChild, GetDevice, 3, 2, 'V') \
    M(ID3D11PixelShader, ID3D11DeviceChild, GetPrivateData, 4, 4, 'D') \
    M(ID3D11PixelShader, ID3D11DeviceChild, SetPrivateData, 5, 4, 'D') \
    M(ID3D11PixelShader, ID3D11DeviceChild, SetPrivateDataInterface, 6, 3, 'D')
#define B11_METHODS_ID3D11GeometryShader(M) \
    M(ID3D11GeometryShader, IUnknown, QueryInterface, 0, 3, 'D') \
    M(ID3D11GeometryShader, IUnknown, AddRef, 1, 1, 'D') \
    M(ID3D11GeometryShader, IUnknown, Release, 2, 1, 'D') \
    M(ID3D11GeometryShader, ID3D11DeviceChild, GetDevice, 3, 2, 'V') \
    M(ID3D11GeometryShader, ID3D11DeviceChild, GetPrivateData, 4, 4, 'D') \
    M(ID3D11GeometryShader, ID3D11DeviceChild, SetPrivateData, 5, 4, 'D') \
    M(ID3D11GeometryShader, ID3D11DeviceChild, SetPrivateDataInterface, 6, 3, 'D')
#define B11_METHODS_ID3D11HullShader(M) \
    M(ID3D11HullShader, IUnknown, QueryInterface, 0, 3, 'D') \
    M(ID3D11HullShader, IUnknown, AddRef, 1, 1, 'D') \
    M(ID3D11HullShader, IUnknown, Release, 2, 1, 'D') \
    M(ID3D11HullShader, ID3D11DeviceChild, GetDevice, 3, 2, 'V') \
    M(ID3D11HullShader, ID3D11DeviceChild, GetPrivateData, 4, 4, 'D') \
    M(ID3D11HullShader, ID3D11DeviceChild, SetPrivateData, 5, 4, 'D') \
    M(ID3D11HullShader, ID3D11DeviceChild, SetPrivateDataInterface, 6, 3, 'D')
#define B11_METHODS_ID3D11DomainShader(M) \
    M(ID3D11DomainShader, IUnknown, QueryInterface, 0, 3, 'D') \
    M(ID3D11DomainShader, IUnknown, AddRef, 1, 1, 'D') \
    M(ID3D11DomainShader, IUnknown, Release, 2, 1, 'D') \
    M(ID3D11DomainShader, ID3D11DeviceChild, GetDevice, 3, 2, 'V') \
    M(ID3D11DomainShader, ID3D11DeviceChild, GetPrivateData, 4, 4, 'D') \
    M(ID3D11DomainShader, ID3D11DeviceChild, SetPrivateData, 5, 4, 'D') \
    M(ID3D11DomainShader, ID3D11DeviceChild, SetPrivateDataInterface, 6, 3, 'D')
#define B11_METHODS_ID3D11ComputeShader(M) \
    M(ID3D11ComputeShader, IUnknown, QueryInterface, 0, 3, 'D') \
    M(ID3D11ComputeShader, IUnknown, AddRef, 1, 1, 'D') \
    M(ID3D11ComputeShader, IUnknown, Release, 2, 1, 'D') \
    M(ID3D11ComputeShader, ID3D11DeviceChild, GetDevice, 3, 2, 'V') \
    M(ID3D11ComputeShader, ID3D11DeviceChild, GetPrivateData, 4, 4, 'D') \
    M(ID3D11ComputeShader, ID3D11DeviceChild, SetPrivateData, 5, 4, 'D') \
    M(ID3D11ComputeShader, ID3D11DeviceChild, SetPrivateDataInterface, 6, 3, 'D')
#define B11_METHODS_ID3D11SamplerState(M) \
    M(ID3D11SamplerState, IUnknown, QueryInterface, 0, 3, 'D') \
    M(ID3D11SamplerState, IUnknown, AddRef, 1, 1, 'D') \
    M(ID3D11SamplerState, IUnknown, Release, 2, 1, 'D') \
    M(ID3D11SamplerState, ID3D11DeviceChild, GetDevice, 3, 2, 'V') \
    M(ID3D11SamplerState, ID3D11DeviceChild, GetPrivateData, 4, 4, 'D') \
    M(ID3D11SamplerState, ID3D11DeviceChild, SetPrivateData, 5, 4, 'D') \
    M(ID3D11SamplerState, ID3D11DeviceChild, SetPrivateDataInterface, 6, 3, 'D') \
    M(ID3D11SamplerState, ID3D11SamplerState, GetDesc, 7, 2, 'V')
#define B11_METHODS_ID3D11RasterizerState(M) \
    M(ID3D11RasterizerState, IUnknown, QueryInterface, 0, 3, 'D') \
    M(ID3D11RasterizerState, IUnknown, AddRef, 1, 1, 'D') \
    M(ID3D11RasterizerState, IUnknown, Release, 2, 1, 'D') \
    M(ID3D11RasterizerState, ID3D11DeviceChild, GetDevice, 3, 2, 'V') \
    M(ID3D11RasterizerState, ID3D11DeviceChild, GetPrivateData, 4, 4, 'D') \
    M(ID3D11RasterizerState, ID3D11DeviceChild, SetPrivateData, 5, 4, 'D') \
    M(ID3D11RasterizerState, ID3D11DeviceChild, SetPrivateDataInterface, 6, 3, 'D') \
    M(ID3D11RasterizerState, ID3D11RasterizerState, GetDesc, 7, 2, 'V')
#define B11_METHODS_ID3D11BlendState(M) \
    M(ID3D11BlendState, IUnknown, QueryInterface, 0, 3, 'D') \
    M(ID3D11BlendState, IUnknown, AddRef, 1, 1, 'D') \
    M(ID3D11BlendState, IUnknown, Release, 2, 1, 'D') \
    M(ID3D11BlendState, ID3D11DeviceChild, GetDevice, 3, 2, 'V') \
    M(ID3D11BlendState, ID3D11DeviceChild, GetPrivateData, 4, 4, 'D') \
    M(ID3D11BlendState, ID3D11DeviceChild, SetPrivateData, 5, 4, 'D') \
    M(ID3D11BlendState, ID3D11DeviceChild, SetPrivateDataInterface, 6, 3, 'D') \
    M(ID3D11BlendState, ID3D11BlendState, GetDesc, 7, 2, 'V')
#define B11_METHODS_ID3D11DepthStencilState(M) \
    M(ID3D11DepthStencilState, IUnknown, QueryInterface, 0, 3, 'D') \
    M(ID3D11DepthStencilState, IUnknown, AddRef, 1, 1, 'D') \
    M(ID3D11DepthStencilState, IUnknown, Release, 2, 1, 'D') \
    M(ID3D11DepthStencilState, ID3D11DeviceChild, GetDevice, 3, 2, 'V') \
    M(ID3D11DepthStencilState, ID3D11DeviceChild, GetPrivateData, 4, 4, 'D') \
    M(ID3D11DepthStencilState, ID3D11DeviceChild, SetPrivateData, 5, 4, 'D') \
    M(ID3D11DepthStencilState, ID3D11DeviceChild, SetPrivateDataInterface, 6, 3, 'D') \
    M(ID3D11DepthStencilState, ID3D11DepthStencilState, GetDesc, 7, 2, 'V')
#define B11_METHODS_ID3D11Asynchronous(M) \
    M(ID3D11Asynchronous, IUnknown, QueryInterface, 0, 3, 'D') \
    M(ID3D11Asynchronous, IUnknown, AddRef, 1, 1, 'D') \
    M(ID3D11Asynchronous, IUnknown, Release, 2, 1, 'D') \
    M(ID3D11Asynchronous, ID3D11DeviceChild, GetDevice, 3, 2, 'V') \
    M(ID3D11Asynchronous, ID3D11DeviceChild, GetPrivateData, 4, 4, 'D') \
    M(ID3D11Asynchronous, ID3D11DeviceChild, SetPrivateData, 5, 4, 'D') \
    M(ID3D11Asynchronous, ID3D11DeviceChild, SetPrivateDataInterface, 6, 3, 'D') \
    M(ID3D11Asynchronous, ID3D11Asynchronous, GetDataSize, 7, 1, 'D')
#define B11_METHODS_ID3D11Query(M) \
    M(ID3D11Query, IUnknown, QueryInterface, 0, 3, 'D') \
    M(ID3D11Query, IUnknown, AddRef, 1, 1, 'D') \
    M(ID3D11Query, IUnknown, Release, 2, 1, 'D') \
    M(ID3D11Query, ID3D11DeviceChild, GetDevice, 3, 2, 'V') \
    M(ID3D11Query, ID3D11DeviceChild, GetPrivateData, 4, 4, 'D') \
    M(ID3D11Query, ID3D11DeviceChild, SetPrivateData, 5, 4, 'D') \
    M(ID3D11Query, ID3D11DeviceChild, SetPrivateDataInterface, 6, 3, 'D') \
    M(ID3D11Query, ID3D11Asynchronous, GetDataSize, 7, 1, 'D') \
    M(ID3D11Query, ID3D11Query, GetDesc, 8, 2, 'V')
#define B11_METHODS_ID3D11Predicate(M) \
    M(ID3D11Predicate, IUnknown, QueryInterface, 0, 3, 'D') \
    M(ID3D11Predicate, IUnknown, AddRef, 1, 1, 'D') \
    M(ID3D11Predicate, IUnknown, Release, 2, 1, 'D') \
    M(ID3D11Predicate, ID3D11DeviceChild, GetDevice, 3, 2, 'V') \
    M(ID3D11Predicate, ID3D11DeviceChild, GetPrivateData, 4, 4, 'D') \
    M(ID3D11Predicate, ID3D11DeviceChild, SetPrivateData, 5, 4, 'D') \
    M(ID3D11Predicate, ID3D11DeviceChild, SetPrivateDataInterface, 6, 3, 'D') \
    M(ID3D11Predicate, ID3D11Asynchronous, GetDataSize, 7, 1, 'D') \
    M(ID3D11Predicate, ID3D11Query, GetDesc, 8, 2, 'V')
#define B11_METHODS_ID3D11Counter(M) \
    M(ID3D11Counter, IUnknown, QueryInterface, 0, 3, 'D') \
    M(ID3D11Counter, IUnknown, AddRef, 1, 1, 'D') \
    M(ID3D11Counter, IUnknown, Release, 2, 1, 'D') \
    M(ID3D11Counter, ID3D11DeviceChild, GetDevice, 3, 2, 'V') \
    M(ID3D11Counter, ID3D11DeviceChild, GetPrivateData, 4, 4, 'D') \
    M(ID3D11Counter, ID3D11DeviceChild, SetPrivateData, 5, 4, 'D') \
    M(ID3D11Counter, ID3D11DeviceChild, SetPrivateDataInterface, 6, 3, 'D') \
    M(ID3D11Counter, ID3D11Asynchronous, GetDataSize, 7, 1, 'D') \
    M(ID3D11Counter, ID3D11Counter, GetDesc, 8, 2, 'V')
#define B11_METHODS_ID3D11ClassInstance(M) \
    M(ID3D11ClassInstance, IUnknown, QueryInterface, 0, 3, 'D') \
    M(ID3D11ClassInstance, IUnknown, AddRef, 1, 1, 'D') \
    M(ID3D11ClassInstance, IUnknown, Release, 2, 1, 'D') \
    M(ID3D11ClassInstance, ID3D11DeviceChild, GetDevice, 3, 2, 'V') \
    M(ID3D11ClassInstance, ID3D11DeviceChild, GetPrivateData, 4, 4, 'D') \
    M(ID3D11ClassInstance, ID3D11DeviceChild, SetPrivateData, 5, 4, 'D') \
    M(ID3D11ClassInstance, ID3D11DeviceChild, SetPrivateDataInterface, 6, 3, 'D') \
    M(ID3D11ClassInstance, ID3D11ClassInstance, GetClassLinkage, 7, 2, 'V') \
    M(ID3D11ClassInstance, ID3D11ClassInstance, GetDesc, 8, 2, 'V') \
    M(ID3D11ClassInstance, ID3D11ClassInstance, GetInstanceName, 9, 3, 'V') \
    M(ID3D11ClassInstance, ID3D11ClassInstance, GetTypeName, 10, 3, 'V')
#define B11_METHODS_ID3D11ClassLinkage(M) \
    M(ID3D11ClassLinkage, IUnknown, QueryInterface, 0, 3, 'D') \
    M(ID3D11ClassLinkage, IUnknown, AddRef, 1, 1, 'D') \
    M(ID3D11ClassLinkage, IUnknown, Release, 2, 1, 'D') \
    M(ID3D11ClassLinkage, ID3D11DeviceChild, GetDevice, 3, 2, 'V') \
    M(ID3D11ClassLinkage, ID3D11DeviceChild, GetPrivateData, 4, 4, 'D') \
    M(ID3D11ClassLinkage, ID3D11DeviceChild, SetPrivateData, 5, 4, 'D') \
    M(ID3D11ClassLinkage, ID3D11DeviceChild, SetPrivateDataInterface, 6, 3, 'D') \
    M(ID3D11ClassLinkage, ID3D11ClassLinkage, GetClassInstance, 7, 4, 'D') \
    M(ID3D11ClassLinkage, ID3D11ClassLinkage, CreateClassInstance, 8, 7, 'D')
#define B11_METHODS_ID3D11CommandList(M) \
    M(ID3D11CommandList, IUnknown, QueryInterface, 0, 3, 'D') \
    M(ID3D11CommandList, IUnknown, AddRef, 1, 1, 'D') \
    M(ID3D11CommandList, IUnknown, Release, 2, 1, 'D') \
    M(ID3D11CommandList, ID3D11DeviceChild, GetDevice, 3, 2, 'V') \
    M(ID3D11CommandList, ID3D11DeviceChild, GetPrivateData, 4, 4, 'D') \
    M(ID3D11CommandList, ID3D11DeviceChild, SetPrivateData, 5, 4, 'D') \
    M(ID3D11CommandList, ID3D11DeviceChild, SetPrivateDataInterface, 6, 3, 'D') \
    M(ID3D11CommandList, ID3D11CommandList, GetContextFlags, 7, 1, 'D')
#define B11_METHODS_ID3D11DeviceContext(M) \
    M(ID3D11DeviceContext, IUnknown, QueryInterface, 0, 3, 'D') \
    M(ID3D11DeviceContext, IUnknown, AddRef, 1, 1, 'D') \
    M(ID3D11DeviceContext, IUnknown, Release, 2, 1, 'D') \
    M(ID3D11DeviceContext, ID3D11DeviceChild, GetDevice, 3, 2, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceChild, GetPrivateData, 4, 4, 'D') \
    M(ID3D11DeviceContext, ID3D11DeviceChild, SetPrivateData, 5, 4, 'D') \
    M(ID3D11DeviceContext, ID3D11DeviceChild, SetPrivateDataInterface, 6, 3, 'D') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, VSSetConstantBuffers, 7, 4, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, PSSetShaderResources, 8, 4, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, PSSetShader, 9, 4, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, PSSetSamplers, 10, 4, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, VSSetShader, 11, 4, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, DrawIndexed, 12, 4, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, Draw, 13, 3, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, Map, 14, 6, 'D') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, Unmap, 15, 3, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, PSSetConstantBuffers, 16, 4, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, IASetInputLayout, 17, 2, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, IASetVertexBuffers, 18, 6, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, IASetIndexBuffer, 19, 4, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, DrawIndexedInstanced, 20, 6, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, DrawInstanced, 21, 5, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, GSSetConstantBuffers, 22, 4, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, GSSetShader, 23, 4, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, IASetPrimitiveTopology, 24, 2, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, VSSetShaderResources, 25, 4, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, VSSetSamplers, 26, 4, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, Begin, 27, 2, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, End, 28, 2, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, GetData, 29, 5, 'D') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, SetPredication, 30, 3, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, GSSetShaderResources, 31, 4, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, GSSetSamplers, 32, 4, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, OMSetRenderTargets, 33, 4, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, OMSetRenderTargetsAndUnorderedAccessViews, 34, 8, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, OMSetBlendState, 35, 4, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, OMSetDepthStencilState, 36, 3, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, SOSetTargets, 37, 4, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, DrawAuto, 38, 1, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, DrawIndexedInstancedIndirect, 39, 3, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, DrawInstancedIndirect, 40, 3, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, Dispatch, 41, 4, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, DispatchIndirect, 42, 3, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, RSSetState, 43, 2, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, RSSetViewports, 44, 3, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, RSSetScissorRects, 45, 3, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, CopySubresourceRegion, 46, 9, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, CopyResource, 47, 3, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, UpdateSubresource, 48, 7, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, CopyStructureCount, 49, 4, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, ClearRenderTargetView, 50, 3, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, ClearUnorderedAccessViewUint, 51, 3, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, ClearUnorderedAccessViewFloat, 52, 3, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, ClearDepthStencilView, 53, 5, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, GenerateMips, 54, 2, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, SetResourceMinLOD, 55, 3, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, GetResourceMinLOD, 56, 2, 'F') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, ResolveSubresource, 57, 6, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, ExecuteCommandList, 58, 3, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, HSSetShaderResources, 59, 4, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, HSSetShader, 60, 4, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, HSSetSamplers, 61, 4, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, HSSetConstantBuffers, 62, 4, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, DSSetShaderResources, 63, 4, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, DSSetShader, 64, 4, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, DSSetSamplers, 65, 4, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, DSSetConstantBuffers, 66, 4, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, CSSetShaderResources, 67, 4, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, CSSetUnorderedAccessViews, 68, 5, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, CSSetShader, 69, 4, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, CSSetSamplers, 70, 4, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, CSSetConstantBuffers, 71, 4, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, VSGetConstantBuffers, 72, 4, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, PSGetShaderResources, 73, 4, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, PSGetShader, 74, 4, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, PSGetSamplers, 75, 4, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, VSGetShader, 76, 4, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, PSGetConstantBuffers, 77, 4, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, IAGetInputLayout, 78, 2, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, IAGetVertexBuffers, 79, 6, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, IAGetIndexBuffer, 80, 4, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, GSGetConstantBuffers, 81, 4, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, GSGetShader, 82, 4, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, IAGetPrimitiveTopology, 83, 2, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, VSGetShaderResources, 84, 4, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, VSGetSamplers, 85, 4, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, GetPredication, 86, 3, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, GSGetShaderResources, 87, 4, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, GSGetSamplers, 88, 4, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, OMGetRenderTargets, 89, 4, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, OMGetRenderTargetsAndUnorderedAccessViews, 90, 7, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, OMGetBlendState, 91, 4, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, OMGetDepthStencilState, 92, 3, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, SOGetTargets, 93, 3, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, RSGetState, 94, 2, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, RSGetViewports, 95, 3, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, RSGetScissorRects, 96, 3, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, HSGetShaderResources, 97, 4, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, HSGetShader, 98, 4, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, HSGetSamplers, 99, 4, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, HSGetConstantBuffers, 100, 4, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, DSGetShaderResources, 101, 4, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, DSGetShader, 102, 4, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, DSGetSamplers, 103, 4, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, DSGetConstantBuffers, 104, 4, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, CSGetShaderResources, 105, 4, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, CSGetUnorderedAccessViews, 106, 4, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, CSGetShader, 107, 4, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, CSGetSamplers, 108, 4, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, CSGetConstantBuffers, 109, 4, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, ClearState, 110, 1, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, Flush, 111, 1, 'V') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, GetType, 112, 1, 'D') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, GetContextFlags, 113, 1, 'D') \
    M(ID3D11DeviceContext, ID3D11DeviceContext, FinishCommandList, 114, 3, 'D')
#define B11_METHODS_ID3D11Device(M) \
    M(ID3D11Device, IUnknown, QueryInterface, 0, 3, 'D') \
    M(ID3D11Device, IUnknown, AddRef, 1, 1, 'D') \
    M(ID3D11Device, IUnknown, Release, 2, 1, 'D') \
    M(ID3D11Device, ID3D11Device, CreateBuffer, 3, 4, 'D') \
    M(ID3D11Device, ID3D11Device, CreateTexture1D, 4, 4, 'D') \
    M(ID3D11Device, ID3D11Device, CreateTexture2D, 5, 4, 'D') \
    M(ID3D11Device, ID3D11Device, CreateTexture3D, 6, 4, 'D') \
    M(ID3D11Device, ID3D11Device, CreateShaderResourceView, 7, 4, 'D') \
    M(ID3D11Device, ID3D11Device, CreateUnorderedAccessView, 8, 4, 'D') \
    M(ID3D11Device, ID3D11Device, CreateRenderTargetView, 9, 4, 'D') \
    M(ID3D11Device, ID3D11Device, CreateDepthStencilView, 10, 4, 'D') \
    M(ID3D11Device, ID3D11Device, CreateInputLayout, 11, 6, 'D') \
    M(ID3D11Device, ID3D11Device, CreateVertexShader, 12, 5, 'D') \
    M(ID3D11Device, ID3D11Device, CreateGeometryShader, 13, 5, 'D') \
    M(ID3D11Device, ID3D11Device, CreateGeometryShaderWithStreamOutput, 14, 10, 'D') \
    M(ID3D11Device, ID3D11Device, CreatePixelShader, 15, 5, 'D') \
    M(ID3D11Device, ID3D11Device, CreateHullShader, 16, 5, 'D') \
    M(ID3D11Device, ID3D11Device, CreateDomainShader, 17, 5, 'D') \
    M(ID3D11Device, ID3D11Device, CreateComputeShader, 18, 5, 'D') \
    M(ID3D11Device, ID3D11Device, CreateClassLinkage, 19, 2, 'D') \
    M(ID3D11Device, ID3D11Device, CreateBlendState, 20, 3, 'D') \
    M(ID3D11Device, ID3D11Device, CreateDepthStencilState, 21, 3, 'D') \
    M(ID3D11Device, ID3D11Device, CreateRasterizerState, 22, 3, 'D') \
    M(ID3D11Device, ID3D11Device, CreateSamplerState, 23, 3, 'D') \
    M(ID3D11Device, ID3D11Device, CreateQuery, 24, 3, 'D') \
    M(ID3D11Device, ID3D11Device, CreatePredicate, 25, 3, 'D') \
    M(ID3D11Device, ID3D11Device, CreateCounter, 26, 3, 'D') \
    M(ID3D11Device, ID3D11Device, CreateDeferredContext, 27, 3, 'D') \
    M(ID3D11Device, ID3D11Device, OpenSharedResource, 28, 4, 'D') \
    M(ID3D11Device, ID3D11Device, CheckFormatSupport, 29, 3, 'D') \
    M(ID3D11Device, ID3D11Device, CheckMultisampleQualityLevels, 30, 4, 'D') \
    M(ID3D11Device, ID3D11Device, CheckCounterInfo, 31, 2, 'V') \
    M(ID3D11Device, ID3D11Device, CheckCounter, 32, 10, 'D') \
    M(ID3D11Device, ID3D11Device, CheckFeatureSupport, 33, 4, 'D') \
    M(ID3D11Device, ID3D11Device, GetPrivateData, 34, 4, 'D') \
    M(ID3D11Device, ID3D11Device, SetPrivateData, 35, 4, 'D') \
    M(ID3D11Device, ID3D11Device, SetPrivateDataInterface, 36, 3, 'D') \
    M(ID3D11Device, ID3D11Device, GetFeatureLevel, 37, 1, 'D') \
    M(ID3D11Device, ID3D11Device, GetCreationFlags, 38, 1, 'D') \
    M(ID3D11Device, ID3D11Device, GetDeviceRemovedReason, 39, 1, 'D') \
    M(ID3D11Device, ID3D11Device, GetImmediateContext, 40, 2, 'V') \
    M(ID3D11Device, ID3D11Device, SetExceptionMode, 41, 2, 'D') \
    M(ID3D11Device, ID3D11Device, GetExceptionMode, 42, 1, 'D')
#define B11_DECLARED(D) \
    D(IUnknown, QueryInterface, 0, 3, 'D', "tgo") \
    D(IUnknown, AddRef, 1, 1, 'D', "t") \
    D(IUnknown, Release, 2, 1, 'D', "t") \
    D(IDXGIObject, SetPrivateData, 3, 4, 'D', "tgvp") \
    D(IDXGIObject, SetPrivateDataInterface, 4, 3, 'D', "tgi") \
    D(IDXGIObject, GetPrivateData, 5, 4, 'D', "tgpp") \
    D(IDXGIObject, GetParent, 6, 3, 'D', "tgo") \
    D(IDXGIDeviceSubObject, GetDevice, 7, 3, 'D', "tgo") \
    D(IDXGIFactory, EnumAdapters, 7, 3, 'D', "tvo") \
    D(IDXGIFactory, MakeWindowAssociation, 8, 3, 'D', "thv") \
    D(IDXGIFactory, GetWindowAssociation, 9, 2, 'D', "tp") \
    D(IDXGIFactory, CreateSwapChain, 10, 4, 'D', "tipo") \
    D(IDXGIFactory, CreateSoftwareAdapter, 11, 3, 'D', "tho") \
    D(IDXGIFactory1, EnumAdapters1, 12, 3, 'D', "tvo") \
    D(IDXGIFactory1, IsCurrent, 13, 1, 'D', "t") \
    D(IDXGIAdapter, EnumOutputs, 7, 3, 'D', "tvo") \
    D(IDXGIAdapter, GetDesc, 8, 2, 'D', "tp") \
    D(IDXGIAdapter, CheckInterfaceSupport, 9, 3, 'D', "tgp") \
    D(IDXGIAdapter1, GetDesc1, 10, 2, 'D', "tp") \
    D(IDXGIOutput, GetDesc, 7, 2, 'D', "tp") \
    D(IDXGIOutput, GetDisplayModeList, 8, 5, 'D', "tvvpp") \
    D(IDXGIOutput, FindClosestMatchingMode, 9, 4, 'D', "tppi") \
    D(IDXGIOutput, WaitForVBlank, 10, 1, 'D', "t") \
    D(IDXGIOutput, TakeOwnership, 11, 3, 'D', "tiv") \
    D(IDXGIOutput, ReleaseOwnership, 12, 1, 'V', "t") \
    D(IDXGIOutput, GetGammaControlCapabilities, 13, 2, 'D', "tp") \
    D(IDXGIOutput, SetGammaControl, 14, 2, 'D', "tp") \
    D(IDXGIOutput, GetGammaControl, 15, 2, 'D', "tp") \
    D(IDXGIOutput, SetDisplaySurface, 16, 2, 'D', "ti") \
    D(IDXGIOutput, GetDisplaySurfaceData, 17, 2, 'D', "ti") \
    D(IDXGIOutput, GetFrameStatistics, 18, 2, 'D', "tp") \
    D(IDXGISwapChain, Present, 8, 3, 'D', "tvv") \
    D(IDXGISwapChain, GetBuffer, 9, 4, 'D', "tvgo") \
    D(IDXGISwapChain, SetFullscreenState, 10, 3, 'D', "tvi") \
    D(IDXGISwapChain, GetFullscreenState, 11, 3, 'D', "tpo") \
    D(IDXGISwapChain, GetDesc, 12, 2, 'D', "tp") \
    D(IDXGISwapChain, ResizeBuffers, 13, 6, 'D', "tvvvvv") \
    D(IDXGISwapChain, ResizeTarget, 14, 2, 'D', "tp") \
    D(IDXGISwapChain, GetContainingOutput, 15, 2, 'D', "to") \
    D(IDXGISwapChain, GetFrameStatistics, 16, 2, 'D', "tp") \
    D(IDXGISwapChain, GetLastPresentCount, 17, 2, 'D', "tp") \
    D(IDXGIDevice, GetAdapter, 7, 2, 'D', "to") \
    D(IDXGIDevice, CreateSurface, 8, 6, 'D', "tpvvpo") \
    D(IDXGIDevice, QueryResourceResidency, 9, 4, 'D', "topv") \
    D(IDXGIDevice, SetGPUThreadPriority, 10, 2, 'D', "tv") \
    D(IDXGIDevice, GetGPUThreadPriority, 11, 2, 'D', "tp") \
    D(IDXGIDevice1, SetMaximumFrameLatency, 12, 2, 'D', "tv") \
    D(IDXGIDevice1, GetMaximumFrameLatency, 13, 2, 'D', "tp") \
    D(ID3D10Blob, GetBufferPointer, 3, 1, 'P', "t") \
    D(ID3D10Blob, GetBufferSize, 4, 1, 'Z', "t") \
    D(ID3D11DeviceChild, GetDevice, 3, 2, 'V', "to") \
    D(ID3D11DeviceChild, GetPrivateData, 4, 4, 'D', "tgpp") \
    D(ID3D11DeviceChild, SetPrivateData, 5, 4, 'D', "tgvp") \
    D(ID3D11DeviceChild, SetPrivateDataInterface, 6, 3, 'D', "tgi") \
    D(ID3D11Resource, GetType, 7, 2, 'V', "tp") \
    D(ID3D11Resource, SetEvictionPriority, 8, 2, 'V', "tv") \
    D(ID3D11Resource, GetEvictionPriority, 9, 1, 'D', "t") \
    D(ID3D11Buffer, GetDesc, 10, 2, 'V', "tp") \
    D(ID3D11Texture1D, GetDesc, 10, 2, 'V', "tp") \
    D(ID3D11Texture2D, GetDesc, 10, 2, 'V', "tp") \
    D(ID3D11Texture3D, GetDesc, 10, 2, 'V', "tp") \
    D(ID3D11View, GetResource, 7, 2, 'V', "to") \
    D(ID3D11RenderTargetView, GetDesc, 8, 2, 'V', "tp") \
    D(ID3D11DepthStencilView, GetDesc, 8, 2, 'V', "tp") \
    D(ID3D11ShaderResourceView, GetDesc, 8, 2, 'V', "tp") \
    D(ID3D11UnorderedAccessView, GetDesc, 8, 2, 'V', "tp") \
    D(ID3D11SamplerState, GetDesc, 7, 2, 'V', "tp") \
    D(ID3D11RasterizerState, GetDesc, 7, 2, 'V', "tp") \
    D(ID3D11BlendState, GetDesc, 7, 2, 'V', "tp") \
    D(ID3D11DepthStencilState, GetDesc, 7, 2, 'V', "tp") \
    D(ID3D11Asynchronous, GetDataSize, 7, 1, 'D', "t") \
    D(ID3D11Query, GetDesc, 8, 2, 'V', "tp") \
    D(ID3D11Counter, GetDesc, 8, 2, 'V', "tp") \
    D(ID3D11ClassInstance, GetClassLinkage, 7, 2, 'V', "to") \
    D(ID3D11ClassInstance, GetDesc, 8, 2, 'V', "tp") \
    D(ID3D11ClassInstance, GetInstanceName, 9, 3, 'V', "tpp") \
    D(ID3D11ClassInstance, GetTypeName, 10, 3, 'V', "tpp") \
    D(ID3D11ClassLinkage, GetClassInstance, 7, 4, 'D', "tsvo") \
    D(ID3D11ClassLinkage, CreateClassInstance, 8, 7, 'D', "tsvvvvo") \
    D(ID3D11CommandList, GetContextFlags, 7, 1, 'D', "t") \
    D(ID3D11DeviceContext, VSSetConstantBuffers, 7, 4, 'V', "tvvo") \
    D(ID3D11DeviceContext, PSSetShaderResources, 8, 4, 'V', "tvvo") \
    D(ID3D11DeviceContext, PSSetShader, 9, 4, 'V', "tiov") \
    D(ID3D11DeviceContext, PSSetSamplers, 10, 4, 'V', "tvvo") \
    D(ID3D11DeviceContext, VSSetShader, 11, 4, 'V', "tiov") \
    D(ID3D11DeviceContext, DrawIndexed, 12, 4, 'V', "tvvv") \
    D(ID3D11DeviceContext, Draw, 13, 3, 'V', "tvv") \
    D(ID3D11DeviceContext, Map, 14, 6, 'D', "tivvvp") \
    D(ID3D11DeviceContext, Unmap, 15, 3, 'V', "tiv") \
    D(ID3D11DeviceContext, PSSetConstantBuffers, 16, 4, 'V', "tvvo") \
    D(ID3D11DeviceContext, IASetInputLayout, 17, 2, 'V', "ti") \
    D(ID3D11DeviceContext, IASetVertexBuffers, 18, 6, 'V', "tvvopp") \
    D(ID3D11DeviceContext, IASetIndexBuffer, 19, 4, 'V', "tivv") \
    D(ID3D11DeviceContext, DrawIndexedInstanced, 20, 6, 'V', "tvvvvv") \
    D(ID3D11DeviceContext, DrawInstanced, 21, 5, 'V', "tvvvv") \
    D(ID3D11DeviceContext, GSSetConstantBuffers, 22, 4, 'V', "tvvo") \
    D(ID3D11DeviceContext, GSSetShader, 23, 4, 'V', "tiov") \
    D(ID3D11DeviceContext, IASetPrimitiveTopology, 24, 2, 'V', "tv") \
    D(ID3D11DeviceContext, VSSetShaderResources, 25, 4, 'V', "tvvo") \
    D(ID3D11DeviceContext, VSSetSamplers, 26, 4, 'V', "tvvo") \
    D(ID3D11DeviceContext, Begin, 27, 2, 'V', "ti") \
    D(ID3D11DeviceContext, End, 28, 2, 'V', "ti") \
    D(ID3D11DeviceContext, GetData, 29, 5, 'D', "tipvv") \
    D(ID3D11DeviceContext, SetPredication, 30, 3, 'V', "tiv") \
    D(ID3D11DeviceContext, GSSetShaderResources, 31, 4, 'V', "tvvo") \
    D(ID3D11DeviceContext, GSSetSamplers, 32, 4, 'V', "tvvo") \
    D(ID3D11DeviceContext, OMSetRenderTargets, 33, 4, 'V', "tvoi") \
    D(ID3D11DeviceContext, OMSetRenderTargetsAndUnorderedAccessViews, 34, 8, 'V', "tvoivvop") \
    D(ID3D11DeviceContext, OMSetBlendState, 35, 4, 'V', "tipv") \
    D(ID3D11DeviceContext, OMSetDepthStencilState, 36, 3, 'V', "tiv") \
    D(ID3D11DeviceContext, SOSetTargets, 37, 4, 'V', "tvop") \
    D(ID3D11DeviceContext, DrawAuto, 38, 1, 'V', "t") \
    D(ID3D11DeviceContext, DrawIndexedInstancedIndirect, 39, 3, 'V', "tiv") \
    D(ID3D11DeviceContext, DrawInstancedIndirect, 40, 3, 'V', "tiv") \
    D(ID3D11DeviceContext, Dispatch, 41, 4, 'V', "tvvv") \
    D(ID3D11DeviceContext, DispatchIndirect, 42, 3, 'V', "tiv") \
    D(ID3D11DeviceContext, RSSetState, 43, 2, 'V', "ti") \
    D(ID3D11DeviceContext, RSSetViewports, 44, 3, 'V', "tvp") \
    D(ID3D11DeviceContext, RSSetScissorRects, 45, 3, 'V', "tvp") \
    D(ID3D11DeviceContext, CopySubresourceRegion, 46, 9, 'V', "tivvvvivp") \
    D(ID3D11DeviceContext, CopyResource, 47, 3, 'V', "tii") \
    D(ID3D11DeviceContext, UpdateSubresource, 48, 7, 'V', "tivppvv") \
    D(ID3D11DeviceContext, CopyStructureCount, 49, 4, 'V', "tivi") \
    D(ID3D11DeviceContext, ClearRenderTargetView, 50, 3, 'V', "tip") \
    D(ID3D11DeviceContext, ClearUnorderedAccessViewUint, 51, 3, 'V', "tip") \
    D(ID3D11DeviceContext, ClearUnorderedAccessViewFloat, 52, 3, 'V', "tip") \
    D(ID3D11DeviceContext, ClearDepthStencilView, 53, 5, 'V', "tivvv") \
    D(ID3D11DeviceContext, GenerateMips, 54, 2, 'V', "ti") \
    D(ID3D11DeviceContext, SetResourceMinLOD, 55, 3, 'V', "tiv") \
    D(ID3D11DeviceContext, GetResourceMinLOD, 56, 2, 'F', "ti") \
    D(ID3D11DeviceContext, ResolveSubresource, 57, 6, 'V', "tivivv") \
    D(ID3D11DeviceContext, ExecuteCommandList, 58, 3, 'V', "tiv") \
    D(ID3D11DeviceContext, HSSetShaderResources, 59, 4, 'V', "tvvo") \
    D(ID3D11DeviceContext, HSSetShader, 60, 4, 'V', "tiov") \
    D(ID3D11DeviceContext, HSSetSamplers, 61, 4, 'V', "tvvo") \
    D(ID3D11DeviceContext, HSSetConstantBuffers, 62, 4, 'V', "tvvo") \
    D(ID3D11DeviceContext, DSSetShaderResources, 63, 4, 'V', "tvvo") \
    D(ID3D11DeviceContext, DSSetShader, 64, 4, 'V', "tiov") \
    D(ID3D11DeviceContext, DSSetSamplers, 65, 4, 'V', "tvvo") \
    D(ID3D11DeviceContext, DSSetConstantBuffers, 66, 4, 'V', "tvvo") \
    D(ID3D11DeviceContext, CSSetShaderResources, 67, 4, 'V', "tvvo") \
    D(ID3D11DeviceContext, CSSetUnorderedAccessViews, 68, 5, 'V', "tvvop") \
    D(ID3D11DeviceContext, CSSetShader, 69, 4, 'V', "tiov") \
    D(ID3D11DeviceContext, CSSetSamplers, 70, 4, 'V', "tvvo") \
    D(ID3D11DeviceContext, CSSetConstantBuffers, 71, 4, 'V', "tvvo") \
    D(ID3D11DeviceContext, VSGetConstantBuffers, 72, 4, 'V', "tvvo") \
    D(ID3D11DeviceContext, PSGetShaderResources, 73, 4, 'V', "tvvo") \
    D(ID3D11DeviceContext, PSGetShader, 74, 4, 'V', "toop") \
    D(ID3D11DeviceContext, PSGetSamplers, 75, 4, 'V', "tvvo") \
    D(ID3D11DeviceContext, VSGetShader, 76, 4, 'V', "toop") \
    D(ID3D11DeviceContext, PSGetConstantBuffers, 77, 4, 'V', "tvvo") \
    D(ID3D11DeviceContext, IAGetInputLayout, 78, 2, 'V', "to") \
    D(ID3D11DeviceContext, IAGetVertexBuffers, 79, 6, 'V', "tvvopp") \
    D(ID3D11DeviceContext, IAGetIndexBuffer, 80, 4, 'V', "topp") \
    D(ID3D11DeviceContext, GSGetConstantBuffers, 81, 4, 'V', "tvvo") \
    D(ID3D11DeviceContext, GSGetShader, 82, 4, 'V', "toop") \
    D(ID3D11DeviceContext, IAGetPrimitiveTopology, 83, 2, 'V', "tp") \
    D(ID3D11DeviceContext, VSGetShaderResources, 84, 4, 'V', "tvvo") \
    D(ID3D11DeviceContext, VSGetSamplers, 85, 4, 'V', "tvvo") \
    D(ID3D11DeviceContext, GetPredication, 86, 3, 'V', "top") \
    D(ID3D11DeviceContext, GSGetShaderResources, 87, 4, 'V', "tvvo") \
    D(ID3D11DeviceContext, GSGetSamplers, 88, 4, 'V', "tvvo") \
    D(ID3D11DeviceContext, OMGetRenderTargets, 89, 4, 'V', "tvoo") \
    D(ID3D11DeviceContext, OMGetRenderTargetsAndUnorderedAccessViews, 90, 7, 'V', "tvoovvo") \
    D(ID3D11DeviceContext, OMGetBlendState, 91, 4, 'V', "topp") \
    D(ID3D11DeviceContext, OMGetDepthStencilState, 92, 3, 'V', "top") \
    D(ID3D11DeviceContext, SOGetTargets, 93, 3, 'V', "tvo") \
    D(ID3D11DeviceContext, RSGetState, 94, 2, 'V', "to") \
    D(ID3D11DeviceContext, RSGetViewports, 95, 3, 'V', "tpp") \
    D(ID3D11DeviceContext, RSGetScissorRects, 96, 3, 'V', "tpp") \
    D(ID3D11DeviceContext, HSGetShaderResources, 97, 4, 'V', "tvvo") \
    D(ID3D11DeviceContext, HSGetShader, 98, 4, 'V', "toop") \
    D(ID3D11DeviceContext, HSGetSamplers, 99, 4, 'V', "tvvo") \
    D(ID3D11DeviceContext, HSGetConstantBuffers, 100, 4, 'V', "tvvo") \
    D(ID3D11DeviceContext, DSGetShaderResources, 101, 4, 'V', "tvvo") \
    D(ID3D11DeviceContext, DSGetShader, 102, 4, 'V', "toop") \
    D(ID3D11DeviceContext, DSGetSamplers, 103, 4, 'V', "tvvo") \
    D(ID3D11DeviceContext, DSGetConstantBuffers, 104, 4, 'V', "tvvo") \
    D(ID3D11DeviceContext, CSGetShaderResources, 105, 4, 'V', "tvvo") \
    D(ID3D11DeviceContext, CSGetUnorderedAccessViews, 106, 4, 'V', "tvvo") \
    D(ID3D11DeviceContext, CSGetShader, 107, 4, 'V', "toop") \
    D(ID3D11DeviceContext, CSGetSamplers, 108, 4, 'V', "tvvo") \
    D(ID3D11DeviceContext, CSGetConstantBuffers, 109, 4, 'V', "tvvo") \
    D(ID3D11DeviceContext, ClearState, 110, 1, 'V', "t") \
    D(ID3D11DeviceContext, Flush, 111, 1, 'V', "t") \
    D(ID3D11DeviceContext, GetType, 112, 1, 'D', "t") \
    D(ID3D11DeviceContext, GetContextFlags, 113, 1, 'D', "t") \
    D(ID3D11DeviceContext, FinishCommandList, 114, 3, 'D', "tvo") \
    D(ID3D11Device, CreateBuffer, 3, 4, 'D', "tppo") \
    D(ID3D11Device, CreateTexture1D, 4, 4, 'D', "tppo") \
    D(ID3D11Device, CreateTexture2D, 5, 4, 'D', "tppo") \
    D(ID3D11Device, CreateTexture3D, 6, 4, 'D', "tppo") \
    D(ID3D11Device, CreateShaderResourceView, 7, 4, 'D', "tipo") \
    D(ID3D11Device, CreateUnorderedAccessView, 8, 4, 'D', "tipo") \
    D(ID3D11Device, CreateRenderTargetView, 9, 4, 'D', "tipo") \
    D(ID3D11Device, CreateDepthStencilView, 10, 4, 'D', "tipo") \
    D(ID3D11Device, CreateInputLayout, 11, 6, 'D', "tpvpvo") \
    D(ID3D11Device, CreateVertexShader, 12, 5, 'D', "tpvio") \
    D(ID3D11Device, CreateGeometryShader, 13, 5, 'D', "tpvio") \
    D(ID3D11Device, CreateGeometryShaderWithStreamOutput, 14, 10, 'D', "tpvpvpvvio") \
    D(ID3D11Device, CreatePixelShader, 15, 5, 'D', "tpvio") \
    D(ID3D11Device, CreateHullShader, 16, 5, 'D', "tpvio") \
    D(ID3D11Device, CreateDomainShader, 17, 5, 'D', "tpvio") \
    D(ID3D11Device, CreateComputeShader, 18, 5, 'D', "tpvio") \
    D(ID3D11Device, CreateClassLinkage, 19, 2, 'D', "to") \
    D(ID3D11Device, CreateBlendState, 20, 3, 'D', "tpo") \
    D(ID3D11Device, CreateDepthStencilState, 21, 3, 'D', "tpo") \
    D(ID3D11Device, CreateRasterizerState, 22, 3, 'D', "tpo") \
    D(ID3D11Device, CreateSamplerState, 23, 3, 'D', "tpo") \
    D(ID3D11Device, CreateQuery, 24, 3, 'D', "tpo") \
    D(ID3D11Device, CreatePredicate, 25, 3, 'D', "tpo") \
    D(ID3D11Device, CreateCounter, 26, 3, 'D', "tpo") \
    D(ID3D11Device, CreateDeferredContext, 27, 3, 'D', "tvo") \
    D(ID3D11Device, OpenSharedResource, 28, 4, 'D', "thgo") \
    D(ID3D11Device, CheckFormatSupport, 29, 3, 'D', "tvp") \
    D(ID3D11Device, CheckMultisampleQualityLevels, 30, 4, 'D', "tvvp") \
    D(ID3D11Device, CheckCounterInfo, 31, 2, 'V', "tp") \
    D(ID3D11Device, CheckCounter, 32, 10, 'D', "tppppppppp") \
    D(ID3D11Device, CheckFeatureSupport, 33, 4, 'D', "tvpv") \
    D(ID3D11Device, GetPrivateData, 34, 4, 'D', "tgpp") \
    D(ID3D11Device, SetPrivateData, 35, 4, 'D', "tgvp") \
    D(ID3D11Device, SetPrivateDataInterface, 36, 3, 'D', "tgi") \
    D(ID3D11Device, GetFeatureLevel, 37, 1, 'D', "t") \
    D(ID3D11Device, GetCreationFlags, 38, 1, 'D', "t") \
    D(ID3D11Device, GetDeviceRemovedReason, 39, 1, 'D', "t") \
    D(ID3D11Device, GetImmediateContext, 40, 2, 'V', "to") \
    D(ID3D11Device, SetExceptionMode, 41, 2, 'D', "tv") \
    D(ID3D11Device, GetExceptionMode, 42, 1, 'D', "t")
#define B11_EXPORTS(E) \
    E("dxgi.dll", CreateDXGIFactory, 2, "go") \
    E("dxgi.dll", CreateDXGIFactory1, 2, "go") \
    E("d3d11.dll", D3D11CreateDevice, 10, "ivhvpvvopo") \
    E("d3d11.dll", D3D11CreateDeviceAndSwapChain, 12, "ivhvpvvpoopo") \
    E("D3DCompiler_42.dll", D3DCompile, 11, "pvspissvvoo") \
    E("D3DCompiler_42.dll", D3DReflect, 4, "pvgo") \
    E("D3DCompiler_42.dll", D3DDisassemble, 5, "pvvso")
/* ---- END GENERATED ---- */

/* The interface the game asks D3DReflect for: these 16 bytes are at image address 0x1190ba0c, the IID
 * argument of the call at 0x1147372a. It is D3DCompiler_42's ID3D11ShaderReflection; the SDK headers
 * describe only the current one, whose IID differs and which d3dcompiler_47 alone accepts. */
static const GUID b11_IID_ID3D11ShaderReflection_42 = {0x17f27486, 0xa342, 0x4d10, {0x88, 0x42, 0xab, 0x08, 0x74, 0xe7, 0xf6, 0x70}};

#define B11_MAX_SLOTS 128u

enum {
#define B11_AS_KIND(name, parent) K_##name,
    B11_IFACES(B11_AS_KIND)
    K_Reflection,
    K_ReflectionCB, /* a constant buffer of a reflection: not a COM object, it lives as long as the reflection */
    K_COUNT
};

typedef struct b11_method {
    d3d11_bridge_fn fn;
    const char *name;
    uint8_t decl; /* interface that declares the method: the name it is registered under */
    uint8_t slot;
    uint8_t nargs;
    char ret;
} b11_method;

#define B11_AS_PROTO(I, D, N, slot, nargs, ret) \
    static uint32_t m_##D##_##N(struct lift_ctx *c, const uint32_t *a); \
    static uint32_t b11_w_##D##_##N(struct lift_ctx *c, const uint32_t *a);
#define B11_AS_PROTOS(name, parent) B11_METHODS_##name(B11_AS_PROTO)
B11_IFACES(B11_AS_PROTOS)

#define B11_AS_METHOD(I, D, N, slot, nargs, ret) {b11_w_##D##_##N, #N, K_##D, slot, nargs, ret},
#define B11_AS_TABLE(name, parent) static const b11_method b11_methods_##name[] = {B11_METHODS_##name(B11_AS_METHOD)};
B11_IFACES(B11_AS_TABLE)

/* The generated slot numbers are the SDK's, and each table covers the whole vtable. */
#define B11_AS_SLOT(I, D, N, slot, nargs, ret) _Static_assert(offsetof(I##Vtbl, N) == (slot) * sizeof(void *), #I "::" #N);
#define B11_AS_SLOTS(name, parent) \
    B11_METHODS_##name(B11_AS_SLOT) \
    _Static_assert(sizeof(name##Vtbl) == sizeof b11_methods_##name / sizeof(b11_method) * sizeof(void *), #name); \
    _Static_assert(sizeof b11_methods_##name / sizeof(b11_method) <= B11_MAX_SLOTS, #name);
B11_IFACES(B11_AS_SLOTS)

/* D3DCompiler_42's reflection interface. The SDK headers do not describe it; the game's use of it does.
 * Both callers of the D3DReflect function (at 0x1145e298 and 0x1145e449) hand the object to the same two
 * functions and then release it:
 *
 *   0x11474d5a  call [vtable + 0x10] (this, index)         slot 4. The result is tested for NULL and is an
 *                                                          object:
 *   0x11474d6d  call [its vtable + 0] (object, &desc)      its slot 0, an HRESULT. desc has 20 bytes of stack;
 *                                                          +0 is read as a string, +4 compared with 3.
 *   0x1147576c, 0x114759b5
 *               call [vtable + 0x18] (this, index, &desc)  slot 6, an HRESULT, called with rising indices
 *                                                          until it fails. desc has 32 bytes of stack; +0 is
 *                                                          read as a string, +4 selects a case (2..5), +8
 *                                                          is stored.
 *
 * In slot, arguments and structure that is GetConstantBufferByIndex, the constant buffer's GetDesc
 * (D3D11_SHADER_BUFFER_DESC: 20 bytes, Name, Type) and GetResourceBindingDesc (D3D11_SHADER_INPUT_BIND_DESC:
 * 32 bytes, Name, Type, BindPoint) of the current interface, and those three are bridged to it. Nothing
 * shows what the other slots are in D3DCompiler_42: they stop the run, registered with 0 arguments. No
 * version of the interface has more slots than the current one. */
#define B11_REFLECTION_SLOTS(S) \
    S(3, 0, 'D', "") S(4, 2, 'P', "tv") S(5, 0, 'D', "") S(6, 3, 'D', "tvp") S(7, 0, 'D', "") S(8, 0, 'D', "") S(9, 0, 'D', "") \
    S(10, 0, 'D', "") S(11, 0, 'D', "") S(12, 0, 'D', "") S(13, 0, 'D', "") S(14, 0, 'D', "") S(15, 0, 'D', "") S(16, 0, 'D', "") \
    S(17, 0, 'D', "") S(18, 0, 'D', "") S(19, 0, 'D', "") S(20, 0, 'D', "") S(21, 0, 'D', "")
#define B11_REFLECTION_CB_SLOTS(S) S(0, 2, 'D', "tp") S(1, 0, 'D', "") S(2, 0, 'D', "")
#define B11_REFLECTION_UNKNOWN(S) \
    S(Reflection, 3) S(Reflection, 5) S(Reflection, 7) S(Reflection, 8) S(Reflection, 9) S(Reflection, 10) S(Reflection, 11) \
    S(Reflection, 12) S(Reflection, 13) S(Reflection, 14) S(Reflection, 15) S(Reflection, 16) S(Reflection, 17) \
    S(Reflection, 18) S(Reflection, 19) S(Reflection, 20) S(Reflection, 21) S(ReflectionCB, 1) S(ReflectionCB, 2)
#define B11_AS_REFLECTION_PROTO(n, nargs, ret, sig) \
    static uint32_t m_Reflection_slot##n(struct lift_ctx *c, const uint32_t *a); \
    static uint32_t b11_w_Reflection_slot##n(struct lift_ctx *c, const uint32_t *a);
#define B11_AS_REFLECTION_CB_PROTO(n, nargs, ret, sig) \
    static uint32_t m_ReflectionCB_slot##n(struct lift_ctx *c, const uint32_t *a); \
    static uint32_t b11_w_ReflectionCB_slot##n(struct lift_ctx *c, const uint32_t *a);
B11_REFLECTION_SLOTS(B11_AS_REFLECTION_PROTO)
B11_REFLECTION_CB_SLOTS(B11_AS_REFLECTION_CB_PROTO)
#define B11_AS_REFLECTION_METHOD(n, nargs, ret, sig) {b11_w_Reflection_slot##n, "slot " #n, K_Reflection, n, nargs, ret},
#define B11_AS_REFLECTION_CB_METHOD(n, nargs, ret, sig) {b11_w_ReflectionCB_slot##n, "slot " #n, K_ReflectionCB, n, nargs, ret},
static const b11_method b11_methods_Reflection[] = {
    {b11_w_IUnknown_QueryInterface, "QueryInterface", K_IUnknown, 0, 3, 'D'},
    {b11_w_IUnknown_AddRef, "AddRef", K_IUnknown, 1, 1, 'D'},
    {b11_w_IUnknown_Release, "Release", K_IUnknown, 2, 1, 'D'},
    B11_REFLECTION_SLOTS(B11_AS_REFLECTION_METHOD)
};
static const b11_method b11_methods_ReflectionCB[] = {B11_REFLECTION_CB_SLOTS(B11_AS_REFLECTION_CB_METHOD)};
_Static_assert(sizeof b11_methods_Reflection / sizeof(b11_method) == sizeof(struct ID3D11ShaderReflectionVtbl) / sizeof(void *),
               "reflection slots");
_Static_assert(sizeof b11_methods_ReflectionCB / sizeof(b11_method) == sizeof(struct ID3D11ShaderReflectionConstantBufferVtbl) / sizeof(void *),
               "reflection constant buffer slots");
_Static_assert(offsetof(struct ID3D11ShaderReflectionVtbl, GetConstantBufferByIndex) == 4 * sizeof(void *) &&
                   offsetof(struct ID3D11ShaderReflectionVtbl, GetResourceBindingDesc) == 6 * sizeof(void *) &&
                   offsetof(struct ID3D11ShaderReflectionConstantBufferVtbl, GetDesc) == 0,
               "the three bridged reflection slots");

typedef struct b11_iface {
    const char *name;
    const GUID *iid;           /* NULL: not a COM interface, never the answer to a QueryInterface */
    const b11_method *methods; /* the whole vtable, inherited slots first */
    uint8_t parent;        /* the root is its own parent */
    uint8_t n_methods;
} b11_iface;

#define B11_AS_IFACE(name, parent) {#name, &IID_##name, b11_methods_##name, K_##parent, (uint8_t)(sizeof b11_methods_##name / sizeof(b11_method))},
static const b11_iface b11_if[K_COUNT] = {
    B11_IFACES(B11_AS_IFACE)
    {"ID3D11ShaderReflection_42", &b11_IID_ID3D11ShaderReflection_42, b11_methods_Reflection, K_IUnknown,
     (uint8_t)(sizeof b11_methods_Reflection / sizeof(b11_method))},
    {"ID3D11ShaderReflectionConstantBuffer_42", NULL, b11_methods_ReflectionCB, K_ReflectionCB,
     (uint8_t)(sizeof b11_methods_ReflectionCB / sizeof(b11_method))},
};

static int b11_is_a(int kind, int base) {
    for (;;) {
        if (kind == base) {
            return 1;
        }
        if (b11_if[kind].parent == kind) {
            return 0;
        }
        kind = b11_if[kind].parent;
    }
}

static int b11_kind_of_iid(const GUID *iid) {
    int k;
    for (k = 0; k < K_COUNT; ++k) {
        if (b11_if[k].iid != NULL && IsEqualGUID(b11_if[k].iid, iid)) {
            return k;
        }
    }
    return -1;
}

/* ---- 2. 32-bit layouts ------------------------------------------------------------------------ */

/* A structure with a pointer, a handle or a SIZE_T is laid out differently for the guest. Each has a g32_
 * twin here, converted field by field. Compiling this file for x86 proves the twins: there they must
 * match the SDK structures in size and in every field offset. */
typedef struct g32_D3D11_SUBRESOURCE_DATA {
    uint32_t pSysMem;
    UINT SysMemPitch;
    UINT SysMemSlicePitch;
} g32_D3D11_SUBRESOURCE_DATA;
typedef struct g32_D3D11_MAPPED_SUBRESOURCE {
    uint32_t pData;
    UINT RowPitch;
    UINT DepthPitch;
} g32_D3D11_MAPPED_SUBRESOURCE;
typedef struct g32_D3D11_INPUT_ELEMENT_DESC {
    uint32_t SemanticName;
    UINT SemanticIndex;
    DXGI_FORMAT Format;
    UINT InputSlot;
    UINT AlignedByteOffset;
    D3D11_INPUT_CLASSIFICATION InputSlotClass;
    UINT InstanceDataStepRate;
} g32_D3D11_INPUT_ELEMENT_DESC;
typedef struct g32_D3D11_SO_DECLARATION_ENTRY {
    UINT Stream;
    uint32_t SemanticName;
    UINT SemanticIndex;
    BYTE StartComponent;
    BYTE ComponentCount;
    BYTE OutputSlot;
} g32_D3D11_SO_DECLARATION_ENTRY;
typedef struct g32_D3D_SHADER_MACRO {
    uint32_t Name;
    uint32_t Definition;
} g32_D3D_SHADER_MACRO;
typedef struct g32_DXGI_SWAP_CHAIN_DESC {
    DXGI_MODE_DESC BufferDesc;
    DXGI_SAMPLE_DESC SampleDesc;
    DXGI_USAGE BufferUsage;
    UINT BufferCount;
    uint32_t OutputWindow;
    BOOL Windowed;
    DXGI_SWAP_EFFECT SwapEffect;
    UINT Flags;
} g32_DXGI_SWAP_CHAIN_DESC;
typedef struct g32_DXGI_ADAPTER_DESC {
    WCHAR Description[128];
    UINT VendorId;
    UINT DeviceId;
    UINT SubSysId;
    UINT Revision;
    uint32_t DedicatedVideoMemory;
    uint32_t DedicatedSystemMemory;
    uint32_t SharedSystemMemory;
    LUID AdapterLuid;
} g32_DXGI_ADAPTER_DESC;
typedef struct g32_DXGI_ADAPTER_DESC1 {
    WCHAR Description[128];
    UINT VendorId;
    UINT DeviceId;
    UINT SubSysId;
    UINT Revision;
    uint32_t DedicatedVideoMemory;
    uint32_t DedicatedSystemMemory;
    uint32_t SharedSystemMemory;
    LUID AdapterLuid;
    UINT Flags;
} g32_DXGI_ADAPTER_DESC1;
typedef struct g32_DXGI_OUTPUT_DESC {
    WCHAR DeviceName[32];
    RECT DesktopCoordinates;
    BOOL AttachedToDesktop;
    DXGI_MODE_ROTATION Rotation;
    uint32_t Monitor;
} g32_DXGI_OUTPUT_DESC;
typedef struct g32_D3D11_SHADER_BUFFER_DESC {
    uint32_t Name;
    D3D_CBUFFER_TYPE Type;
    UINT Variables;
    UINT Size;
    UINT uFlags;
} g32_D3D11_SHADER_BUFFER_DESC;
typedef struct g32_D3D11_SHADER_INPUT_BIND_DESC {
    uint32_t Name;
    D3D_SHADER_INPUT_TYPE Type;
    UINT BindPoint;
    UINT BindCount;
    UINT uFlags;
    D3D_RESOURCE_RETURN_TYPE ReturnType;
    D3D_SRV_DIMENSION Dimension;
    UINT NumSamples;
} g32_D3D11_SHADER_INPUT_BIND_DESC;

#define B11_G32_SIZE(T, n) _Static_assert(sizeof(g32_##T) == (n), "g32_" #T)
#ifdef _M_IX86
#define B11_G32_FIELD(T, f) \
    _Static_assert(sizeof(g32_##T) == sizeof(T) && offsetof(g32_##T, f) == offsetof(T, f) && \
                       sizeof(((g32_##T *)0)->f) == sizeof(((T *)0)->f), \
                   #T "." #f)
#else
#define B11_G32_FIELD(T, f) _Static_assert(1, "proved by the x86 compile")
#endif

B11_G32_SIZE(D3D11_SUBRESOURCE_DATA, 12);
B11_G32_FIELD(D3D11_SUBRESOURCE_DATA, pSysMem);
B11_G32_FIELD(D3D11_SUBRESOURCE_DATA, SysMemPitch);
B11_G32_FIELD(D3D11_SUBRESOURCE_DATA, SysMemSlicePitch);
B11_G32_SIZE(D3D11_MAPPED_SUBRESOURCE, 12);
B11_G32_FIELD(D3D11_MAPPED_SUBRESOURCE, pData);
B11_G32_FIELD(D3D11_MAPPED_SUBRESOURCE, RowPitch);
B11_G32_FIELD(D3D11_MAPPED_SUBRESOURCE, DepthPitch);
B11_G32_SIZE(D3D11_INPUT_ELEMENT_DESC, 28);
B11_G32_FIELD(D3D11_INPUT_ELEMENT_DESC, SemanticName);
B11_G32_FIELD(D3D11_INPUT_ELEMENT_DESC, SemanticIndex);
B11_G32_FIELD(D3D11_INPUT_ELEMENT_DESC, Format);
B11_G32_FIELD(D3D11_INPUT_ELEMENT_DESC, InputSlot);
B11_G32_FIELD(D3D11_INPUT_ELEMENT_DESC, AlignedByteOffset);
B11_G32_FIELD(D3D11_INPUT_ELEMENT_DESC, InputSlotClass);
B11_G32_FIELD(D3D11_INPUT_ELEMENT_DESC, InstanceDataStepRate);
B11_G32_SIZE(D3D11_SO_DECLARATION_ENTRY, 16);
B11_G32_FIELD(D3D11_SO_DECLARATION_ENTRY, Stream);
B11_G32_FIELD(D3D11_SO_DECLARATION_ENTRY, SemanticName);
B11_G32_FIELD(D3D11_SO_DECLARATION_ENTRY, SemanticIndex);
B11_G32_FIELD(D3D11_SO_DECLARATION_ENTRY, StartComponent);
B11_G32_FIELD(D3D11_SO_DECLARATION_ENTRY, ComponentCount);
B11_G32_FIELD(D3D11_SO_DECLARATION_ENTRY, OutputSlot);
B11_G32_SIZE(D3D_SHADER_MACRO, 8);
B11_G32_FIELD(D3D_SHADER_MACRO, Name);
B11_G32_FIELD(D3D_SHADER_MACRO, Definition);
B11_G32_SIZE(DXGI_SWAP_CHAIN_DESC, 60);
B11_G32_FIELD(DXGI_SWAP_CHAIN_DESC, BufferDesc);
B11_G32_FIELD(DXGI_SWAP_CHAIN_DESC, SampleDesc);
B11_G32_FIELD(DXGI_SWAP_CHAIN_DESC, BufferUsage);
B11_G32_FIELD(DXGI_SWAP_CHAIN_DESC, BufferCount);
B11_G32_FIELD(DXGI_SWAP_CHAIN_DESC, OutputWindow);
B11_G32_FIELD(DXGI_SWAP_CHAIN_DESC, Windowed);
B11_G32_FIELD(DXGI_SWAP_CHAIN_DESC, SwapEffect);
B11_G32_FIELD(DXGI_SWAP_CHAIN_DESC, Flags);
B11_G32_SIZE(DXGI_ADAPTER_DESC, 292);
B11_G32_FIELD(DXGI_ADAPTER_DESC, Description);
B11_G32_FIELD(DXGI_ADAPTER_DESC, VendorId);
B11_G32_FIELD(DXGI_ADAPTER_DESC, DeviceId);
B11_G32_FIELD(DXGI_ADAPTER_DESC, SubSysId);
B11_G32_FIELD(DXGI_ADAPTER_DESC, Revision);
B11_G32_FIELD(DXGI_ADAPTER_DESC, DedicatedVideoMemory);
B11_G32_FIELD(DXGI_ADAPTER_DESC, DedicatedSystemMemory);
B11_G32_FIELD(DXGI_ADAPTER_DESC, SharedSystemMemory);
B11_G32_FIELD(DXGI_ADAPTER_DESC, AdapterLuid);
B11_G32_SIZE(DXGI_ADAPTER_DESC1, 296);
B11_G32_FIELD(DXGI_ADAPTER_DESC1, Description);
B11_G32_FIELD(DXGI_ADAPTER_DESC1, VendorId);
B11_G32_FIELD(DXGI_ADAPTER_DESC1, DeviceId);
B11_G32_FIELD(DXGI_ADAPTER_DESC1, SubSysId);
B11_G32_FIELD(DXGI_ADAPTER_DESC1, Revision);
B11_G32_FIELD(DXGI_ADAPTER_DESC1, DedicatedVideoMemory);
B11_G32_FIELD(DXGI_ADAPTER_DESC1, DedicatedSystemMemory);
B11_G32_FIELD(DXGI_ADAPTER_DESC1, SharedSystemMemory);
B11_G32_FIELD(DXGI_ADAPTER_DESC1, AdapterLuid);
B11_G32_FIELD(DXGI_ADAPTER_DESC1, Flags);
B11_G32_SIZE(DXGI_OUTPUT_DESC, 92);
B11_G32_FIELD(DXGI_OUTPUT_DESC, DeviceName);
B11_G32_FIELD(DXGI_OUTPUT_DESC, DesktopCoordinates);
B11_G32_FIELD(DXGI_OUTPUT_DESC, AttachedToDesktop);
B11_G32_FIELD(DXGI_OUTPUT_DESC, Rotation);
B11_G32_FIELD(DXGI_OUTPUT_DESC, Monitor);
B11_G32_SIZE(D3D11_SHADER_BUFFER_DESC, 20); /* the stack the game gives it at 0x11474d67 */
B11_G32_FIELD(D3D11_SHADER_BUFFER_DESC, Name);
B11_G32_FIELD(D3D11_SHADER_BUFFER_DESC, Type);
B11_G32_FIELD(D3D11_SHADER_BUFFER_DESC, Variables);
B11_G32_FIELD(D3D11_SHADER_BUFFER_DESC, Size);
B11_G32_FIELD(D3D11_SHADER_BUFFER_DESC, uFlags);
B11_G32_SIZE(D3D11_SHADER_INPUT_BIND_DESC, 32); /* the stack the game gives it at 0x1147575a */
B11_G32_FIELD(D3D11_SHADER_INPUT_BIND_DESC, Name);
B11_G32_FIELD(D3D11_SHADER_INPUT_BIND_DESC, Type);
B11_G32_FIELD(D3D11_SHADER_INPUT_BIND_DESC, BindPoint);
B11_G32_FIELD(D3D11_SHADER_INPUT_BIND_DESC, BindCount);
B11_G32_FIELD(D3D11_SHADER_INPUT_BIND_DESC, uFlags);
B11_G32_FIELD(D3D11_SHADER_INPUT_BIND_DESC, ReturnType);
B11_G32_FIELD(D3D11_SHADER_INPUT_BIND_DESC, Dimension);
B11_G32_FIELD(D3D11_SHADER_INPUT_BIND_DESC, NumSamples);

/* Every other structure the bridged methods take is passed through as a pointer into guest memory. That
 * is right only if x86 and x64 lay it out identically: no pointer, handle or SIZE_T inside, and the same
 * size, which both compiles assert here. */
#define B11_SAME(T, n) _Static_assert(sizeof(T) == (n), #T " differs between x86 and x64")
B11_SAME(GUID, 16);
B11_SAME(LUID, 8);
B11_SAME(RECT, 16);
B11_SAME(LARGE_INTEGER, 8);
B11_SAME(DXGI_MODE_DESC, 28);
B11_SAME(DXGI_SAMPLE_DESC, 8);
B11_SAME(DXGI_FRAME_STATISTICS, 32);
B11_SAME(DXGI_GAMMA_CONTROL, 12324);
B11_SAME(DXGI_GAMMA_CONTROL_CAPABILITIES, 4116);
B11_SAME(DXGI_RESIDENCY, 4);
B11_SAME(D3D_FEATURE_LEVEL, 4);
B11_SAME(D3D11_BUFFER_DESC, 24);
B11_SAME(D3D11_TEXTURE1D_DESC, 32);
B11_SAME(D3D11_TEXTURE2D_DESC, 44);
B11_SAME(D3D11_TEXTURE3D_DESC, 36);
B11_SAME(D3D11_SHADER_RESOURCE_VIEW_DESC, 24);
B11_SAME(D3D11_RENDER_TARGET_VIEW_DESC, 20);
B11_SAME(D3D11_DEPTH_STENCIL_VIEW_DESC, 24);
B11_SAME(D3D11_UNORDERED_ACCESS_VIEW_DESC, 20);
B11_SAME(D3D11_SAMPLER_DESC, 52);
B11_SAME(D3D11_RASTERIZER_DESC, 40);
B11_SAME(D3D11_BLEND_DESC, 264);
B11_SAME(D3D11_DEPTH_STENCIL_DESC, 52);
B11_SAME(D3D11_QUERY_DESC, 8);
B11_SAME(D3D11_COUNTER_DESC, 8);
B11_SAME(D3D11_COUNTER_INFO, 12);
B11_SAME(D3D11_CLASS_INSTANCE_DESC, 32);
B11_SAME(D3D11_VIEWPORT, 24);
B11_SAME(D3D11_BOX, 24);
B11_SAME(D3D11_QUERY_DATA_TIMESTAMP_DISJOINT, 16);
B11_SAME(D3D11_QUERY_DATA_PIPELINE_STATISTICS, 88);
B11_SAME(D3D11_QUERY_DATA_SO_STATISTICS, 16);
_Static_assert(offsetof(DXGI_FRAME_STATISTICS, SyncQPCTime) == 16, "DXGI_FRAME_STATISTICS");
_Static_assert(offsetof(D3D11_QUERY_DATA_TIMESTAMP_DISJOINT, Disjoint) == 8, "D3D11_QUERY_DATA_TIMESTAMP_DISJOINT");

/* ---- 3. guest objects -------------------------------------------------------------------------- */

static d3d11_bridge_host_t b11_host;
static CRITICAL_SECTION b11_lock;

#define B11_GP(x) ((void *)(uintptr_t)(uint32_t)(x)) /* guest address -> host pointer */
#define B11_P(i) B11_GP(a[i])                           /* argument i as a pointer into guest memory */
#define B11_HND(x) ((void *)(intptr_t)(int32_t)(x)) /* a window or kernel handle: 32 significant bits, sign-extended */
#define B11_NONE 0xffffffffu
#define B11_MAX_PTRS 256u /* no Direct3D 11 call takes a longer array of interface pointers */

static uint32_t b11_rd32(uint32_t p) { return *(const uint32_t *)B11_GP(p); }
static void b11_wr32(uint32_t p, uint32_t v) { *(uint32_t *)B11_GP(p) = v; }

/* Private-data interface a host object holds for as long as it exists. Its last Release is how the bridge
 * learns that the host pointer is gone. */
typedef struct b11_notifier {
    const IUnknownVtbl *lpVtbl;
    volatile LONG refs;
    uint32_t index, serial; /* the object entry this stands for */
} b11_notifier;

/* A guest object is two dwords of guest memory: the guest vtable, and the index of its entry here. */
typedef struct b11_object {
    IUnknown *host; /* NULL: free entry */
    b11_notifier *note; /* NULL: the entry goes when Release returns 0 */
    uint32_t guest;
    uint32_t blob;   /* ID3D10Blob: the guest's copy of the buffer */
    uint32_t serial; /* never reused, so a stale index is detected */
    uint32_t owner;  /* serial of the object this one is a part of and goes with; 0: a COM object of its own */
    uint32_t next;   /* index + 1 of the next entry in the hash chain, or in the free list */
    uint8_t kind;    /* widest interface this pointer has been handed to the guest as */
} b11_object;

/* A string a reflection returned, copied to guest memory for as long as the reflection lives. */
typedef struct b11_text {
    uint32_t owner, guest;
} b11_text;

static b11_object *b11_obj;
static uint32_t b11_obj_cap, b11_obj_free, b11_obj_live, b11_serial;
static uint32_t *b11_bucket, b11_bucket_n; /* host pointer -> index + 1 */
static b11_text *b11_texts;
static uint32_t b11_text_n, b11_text_cap;
static uint32_t *b11_dead, b11_dead_n, b11_dead_cap; /* guest blocks to free at the next bridge call */
static volatile LONG b11_vtbl[K_COUNT], b11_method_va[K_COUNT][B11_MAX_SLOTS]; /* guest addresses; 0: not made yet */

/* The private-data name of a notifier; Data1 is the object's serial, so two interfaces of one host object
 * (ID3D11Device and its IDXGIDevice share a store) never replace each other's. */
static const GUID b11_note_id = {0u, 0x4252, 0x3131, {0x9a, 0x3c, 0x52, 0x4f, 0x4d, 0x45, 0x32, 0x00}};

static uint32_t *b11_bucket_for(const void *host) {
    return &b11_bucket[(uint32_t)((uint64_t)((uintptr_t)host >> 3) * 0x9e3779b97f4a7c15ull >> 40) & (b11_bucket_n - 1u)];
}

static int b11_table_grow(void) {
    uint32_t cap = b11_obj_cap != 0u ? b11_obj_cap * 2u : 256u, i;
    b11_object *obj = realloc(b11_obj, cap * sizeof *obj);
    uint32_t *bucket;
    if (obj == NULL) {
        return 0;
    }
    b11_obj = obj;
    bucket = calloc(cap, sizeof *bucket);
    if (bucket == NULL) {
        return 0;
    }
    for (i = b11_obj_cap; i < cap; ++i) {
        memset(&obj[i], 0, sizeof obj[i]);
        obj[i].next = b11_obj_free;
        b11_obj_free = i + 1u;
    }
    free(b11_bucket);
    b11_bucket = bucket;
    b11_bucket_n = b11_obj_cap = cap;
    for (i = 0u; i < cap; ++i) {
        if (obj[i].host != NULL) {
            uint32_t *b = b11_bucket_for(obj[i].host);
            obj[i].next = *b;
            *b = i + 1u;
        }
    }
    return 1;
}

/* A part of another object is known by its pointer and its owner: the host can hand the same pointer out
 * for two owners (the constant buffer that stands for "no such buffer"), and each must outlive only its own. */
static uint32_t b11_find_host(const IUnknown *host, uint32_t owner) {
    uint32_t i;
    for (i = b11_bucket_n != 0u ? *b11_bucket_for(host) : 0u; i != 0u; i = b11_obj[i - 1u].next) {
        if (b11_obj[i - 1u].host == host && b11_obj[i - 1u].owner == owner) {
            return i - 1u;
        }
    }
    return B11_NONE;
}

static b11_object *b11_object_at(uint32_t guest) {
    uint32_t i;
    if (guest == 0u) {
        return NULL;
    }
    i = b11_rd32(guest + 4u);
    return i < b11_obj_cap && b11_obj[i].host != NULL && b11_obj[i].guest == guest ? &b11_obj[i] : NULL;
}

static void b11_dead_push(uint32_t p) {
    if (b11_dead_n == b11_dead_cap) {
        uint32_t cap = b11_dead_cap != 0u ? b11_dead_cap * 2u : 64u;
        uint32_t *dead = realloc(b11_dead, cap * sizeof *dead);
        if (dead == NULL) {
            return; /* the guest block leaks */
        }
        b11_dead = dead;
        b11_dead_cap = cap;
    }
    b11_dead[b11_dead_n++] = p;
}

/* Forgets an object, and with a reflection its constant buffers and strings; the guest memory is freed by
 * the next b11_drain. b11_lock held. */
static void b11_retire(b11_object *o) {
    uint32_t self = (uint32_t)(o - b11_obj) + 1u, *link = b11_bucket_for(o->host), i, kept = 0u;
    const uint32_t parts_of = o->kind == K_Reflection ? o->serial : 0u;
    while (*link != self) {
        link = &b11_obj[*link - 1u].next;
    }
    *link = o->next;
    b11_dead_push(o->guest);
    if (o->blob != 0u) {
        b11_dead_push(o->blob);
    }
    memset(o, 0, sizeof *o);
    o->next = b11_obj_free;
    b11_obj_free = self;
    --b11_obj_live;
    if (parts_of == 0u) {
        return;
    }
    for (i = 0u; i < b11_obj_cap; ++i) {
        if (b11_obj[i].host != NULL && b11_obj[i].owner == parts_of) {
            b11_retire(&b11_obj[i]);
        }
    }
    for (i = 0u; i < b11_text_n; ++i) {
        if (b11_texts[i].owner == parts_of) {
            b11_dead_push(b11_texts[i].guest);
        } else {
            b11_texts[kept++] = b11_texts[i];
        }
    }
    b11_text_n = kept;
}

static void b11_drain(void) {
    uint32_t batch[32], n, i;
    do {
        EnterCriticalSection(&b11_lock);
        n = b11_dead_n < 32u ? b11_dead_n : 32u;
        b11_dead_n -= n;
        for (i = 0u; i < n; ++i) {
            batch[i] = b11_dead[b11_dead_n + i];
        }
        LeaveCriticalSection(&b11_lock);
        for (i = 0u; i < n; ++i) {
            b11_host.gfree(batch[i]);
        }
    } while (n == 32u);
}

static HRESULT STDMETHODCALLTYPE b11_note_QueryInterface(IUnknown *This, REFIID riid, void **out) {
    if (out == NULL) {
        return E_POINTER;
    }
    *out = NULL;
    if (!IsEqualGUID(riid, &IID_IUnknown)) {
        return E_NOINTERFACE;
    }
    InterlockedIncrement(&((b11_notifier *)This)->refs);
    *out = This;
    return S_OK;
}
static ULONG STDMETHODCALLTYPE b11_note_AddRef(IUnknown *This) { return (ULONG)InterlockedIncrement(&((b11_notifier *)This)->refs); }
/* Runs on whatever thread destroys the host object, inside the host's locks: it only edits the table. */
static ULONG STDMETHODCALLTYPE b11_note_Release(IUnknown *This) {
    b11_notifier *n = (b11_notifier *)This;
    LONG left = InterlockedDecrement(&n->refs);
    if (left == 0) {
        EnterCriticalSection(&b11_lock);
        if (n->index < b11_obj_cap && b11_obj[n->index].host != NULL && b11_obj[n->index].serial == n->serial) {
            b11_retire(&b11_obj[n->index]);
        }
        LeaveCriticalSection(&b11_lock);
        free(n);
    }
    return (ULONG)left;
}
static const IUnknownVtbl b11_note_vtbl = {b11_note_QueryInterface, b11_note_AddRef, b11_note_Release};

/* Which SetPrivateDataInterface reaches an object of this kind; 0 when it has no private data. */
static int b11_note_route(int kind) {
    return b11_is_a(kind, K_ID3D11DeviceChild) ? 1 : kind == K_ID3D11Device ? 2 : b11_is_a(kind, K_IDXGIObject) ? 3 : 0;
}

static void b11_attach(IUnknown *host, int kind, uint32_t index, uint32_t serial) {
    GUID id = b11_note_id;
    b11_notifier *n;
    IUnknown *via = NULL;
    HRESULT hr;
    int claimed = 0, route = b11_note_route(kind);
    if (kind == K_IUnknown) { /* the IUnknown of some object: find the interface that has its private data */
        route = SUCCEEDED(IUnknown_QueryInterface(host, &IID_ID3D11DeviceChild, (void **)&via)) ? 1
                : SUCCEEDED(IUnknown_QueryInterface(host, &IID_ID3D11Device, (void **)&via)) ? 2
                : SUCCEEDED(IUnknown_QueryInterface(host, &IID_IDXGIObject, (void **)&via)) ? 3
                                                                                            : 0;
    }
    n = route != 0 ? malloc(sizeof *n) : NULL;
    if (n == NULL) { /* the object then goes when Release returns 0 */
        if (via != NULL) {
            IUnknown_Release(via);
        }
        return;
    }
    n->lpVtbl = &b11_note_vtbl;
    n->refs = 1;
    n->index = index;
    n->serial = serial;
    id.Data1 = serial;
    EnterCriticalSection(&b11_lock);
    if (b11_obj[index].host == host && b11_obj[index].serial == serial && b11_obj[index].note == NULL) {
        b11_obj[index].note = n;
        claimed = 1;
    }
    LeaveCriticalSection(&b11_lock);
    if (!claimed) {
        hr = E_FAIL;
    } else if (route == 1) {
        hr = ID3D11DeviceChild_SetPrivateDataInterface((ID3D11DeviceChild *)(via != NULL ? via : host), &id, (IUnknown *)n);
    } else if (route == 2) {
        hr = ID3D11Device_SetPrivateDataInterface((ID3D11Device *)(via != NULL ? via : host), &id, (IUnknown *)n);
    } else {
        hr = IDXGIObject_SetPrivateDataInterface((IDXGIObject *)(via != NULL ? via : host), &id, (IUnknown *)n);
    }
    if (via != NULL) {
        IUnknown_Release(via);
    }
    if (!claimed) {
        free(n);
        return;
    }
    if (FAILED(hr)) {
        EnterCriticalSection(&b11_lock);
        if (b11_obj[index].host == host && b11_obj[index].serial == serial) {
            b11_obj[index].note = NULL;
        }
        LeaveCriticalSection(&b11_lock);
        free(n);
        return;
    }
    b11_note_Release((IUnknown *)n); /* the host object now holds the only reference */
}

/* Guest vtable of an interface, built on first use. Called without b11_lock, as every host callback is.
 * Two threads can build the same vtable at once: both register the methods (the host gives one method one
 * address), the vtable stored first is the one every object gets, and the other is freed. */
static uint32_t b11_vtbl_of(int kind) {
    const b11_iface *f = &b11_if[kind];
    uint32_t i, v = (uint32_t)b11_vtbl[kind];
    LONG first;
    if (v != 0u) {
        return v;
    }
    v = b11_host.galloc(4u * f->n_methods, 1);
    for (i = 0u; v != 0u && i < f->n_methods; ++i) {
        const b11_method *m = &f->methods[i];
        volatile LONG *known = &b11_method_va[m->decl][m->slot];
        uint32_t va = (uint32_t)*known;
        if (va == 0u) {
            va = b11_host.register_method(b11_if[m->decl].name, m->slot, m->nargs, m->fn);
            first = InterlockedCompareExchange(known, (LONG)va, 0);
            if (first != 0) {
                va = (uint32_t)first;
            }
        }
        if (va == 0u) { /* the host could not register the method */
            b11_host.gfree(v);
            return 0u;
        }
        b11_wr32(v + 4u * i, va);
    }
    if (v == 0u) {
        return 0u;
    }
    first = InterlockedCompareExchange(&b11_vtbl[kind], (LONG)v, 0);
    if (first != 0) {
        b11_host.gfree(v);
        v = (uint32_t)first;
    }
    return v;
}

typedef struct b11_found {
    uint32_t index, serial, owner, blob;
    int kind;
} b11_found;

static int b11_alive(const b11_found *f) { return b11_obj[f->index].host != NULL && b11_obj[f->index].serial == f->serial; }

/* The guest object for a host interface pointer of this kind; takes over one reference, which becomes
 * the guest's. The same host pointer always gives the same guest object: if it is already known under a
 * base interface, that object's vtable is widened in place.
 * With part_of, the pointer is not a COM object but a part of that one: no reference, and it goes with it. */
static uint32_t b11_wrap_part(void *ptr, int kind, const b11_found *part_of) {
    IUnknown *host = ptr;
    const void *blob_data = NULL;
    size_t blob_size = 0u;
    const uint32_t owner = part_of != NULL ? part_of->serial : 0u;
    uint32_t guest = 0u, index = B11_NONE, serial = 0u, v, fresh = 0u, fresh_blob = 0u;
    int clash = -1, failed = 0, want_note = 0, allocated = 0;
    if (host == NULL) {
        return 0u;
    }
    if (kind == K_ID3D11Resource) { /* the guest may cast the pointer to what the resource really is */
        D3D11_RESOURCE_DIMENSION dim = D3D11_RESOURCE_DIMENSION_UNKNOWN;
        ID3D11Resource_GetType((ID3D11Resource *)host, &dim);
        kind = dim == D3D11_RESOURCE_DIMENSION_BUFFER      ? K_ID3D11Buffer
               : dim == D3D11_RESOURCE_DIMENSION_TEXTURE1D ? K_ID3D11Texture1D
               : dim == D3D11_RESOURCE_DIMENSION_TEXTURE2D ? K_ID3D11Texture2D
               : dim == D3D11_RESOURCE_DIMENSION_TEXTURE3D ? K_ID3D11Texture3D
                                                           : K_ID3D11Resource;
    }
    if (kind == K_ID3D10Blob) {
        blob_data = ID3D10Blob_GetBufferPointer((ID3D10Blob *)host);
        blob_size = ID3D10Blob_GetBufferSize((ID3D10Blob *)host);
    }
    v = b11_vtbl_of(kind);
    for (;;) {
        EnterCriticalSection(&b11_lock);
        index = b11_find_host(host, owner);
        if (part_of != NULL && !b11_alive(part_of)) { /* the guest released the owner on another thread */
            index = B11_NONE;
            failed = 1;
        } else if (index != B11_NONE) {
            b11_object *o = &b11_obj[index];
            if (kind != o->kind && b11_is_a(kind, o->kind)) {
                if (v != 0u) {
                    o->kind = (uint8_t)kind;
                    b11_wr32(o->guest, v);
                } else {
                    failed = 1;
                }
            } else if (!b11_is_a(o->kind, kind)) {
                clash = o->kind;
            }
            kind = clash < 0 ? o->kind : kind;
            guest = o->guest;
            serial = o->serial;
            want_note = o->note == NULL;
        } else if (fresh != 0u && (b11_obj_free != 0u || b11_table_grow())) {
            b11_object *o;
            uint32_t *b = b11_bucket_for(host);
            index = b11_obj_free - 1u;
            o = &b11_obj[index];
            b11_obj_free = o->next;
            o->host = host;
            o->note = NULL;
            o->guest = guest = fresh;
            o->blob = fresh_blob;
            o->serial = serial = ++b11_serial;
            o->owner = owner;
            o->kind = (uint8_t)kind;
            o->next = *b;
            *b = index + 1u;
            ++b11_obj_live;
            b11_wr32(guest, v);
            b11_wr32(guest + 4u, index);
            fresh = fresh_blob = 0u;
            want_note = 1;
        } else if (allocated) {
            failed = 1;
        } else { /* a new object: its guest memory is allocated outside the lock, then the table is looked at again */
            LeaveCriticalSection(&b11_lock);
            allocated = 1;
            if (v != 0u && blob_size <= 0x7fffffffu) {
                fresh = b11_host.galloc(8u, 1);
            }
            if (fresh != 0u && kind == K_ID3D10Blob) {
                fresh_blob = b11_host.galloc(blob_size != 0u ? (uint32_t)blob_size : 1u, 0);
                if (fresh_blob != 0u) {
                    memcpy(B11_GP(fresh_blob), blob_data, blob_size);
                } else {
                    b11_host.gfree(fresh);
                    fresh = 0u;
                }
            }
            continue;
        }
        LeaveCriticalSection(&b11_lock);
        break;
    }
    if (fresh != 0u) { /* another thread wrapped the same pointer first, or the table could not grow */
        b11_host.gfree(fresh);
        if (fresh_blob != 0u) {
            b11_host.gfree(fresh_blob);
        }
    }
    if (clash >= 0 || failed) {
        if (part_of == NULL) {
            IUnknown_Release(host);
        }
        if (clash >= 0) {
            b11_host.stop("host object %p is bridged as %s and was returned as %s", (void *)host, b11_if[clash].name, b11_if[kind].name);
        } else {
            b11_host.stop("no guest memory for a %s object, or the object it belongs to is gone", b11_if[kind].name);
        }
        return 0u;
    }
    if (want_note && (b11_note_route(kind) != 0 || kind == K_IUnknown)) {
        b11_attach(host, kind, index, serial);
    }
    return guest;
}
static uint32_t b11_wrap_out(void *ptr, int kind) { return b11_wrap_part(ptr, kind, NULL); }

/* Host interface pointer of a guest object that must be (or derive from) the interface `need`; NULL
 * after stopping the run when it is not. */
static void *b11_lookup(uint32_t guest, int need, b11_found *f) {
    b11_object *o;
    IUnknown *host = NULL;
    int kind = -1;
    if (b11_dead_n != 0u) {
        b11_drain();
    }
    EnterCriticalSection(&b11_lock);
    o = b11_object_at(guest);
    if (o != NULL) {
        kind = o->kind;
        if (b11_is_a(kind, need)) {
            host = o->host;
            if (f != NULL) {
                f->index = (uint32_t)(o - b11_obj);
                f->serial = o->serial;
                f->owner = o->owner;
                f->blob = o->blob;
                f->kind = kind;
            }
        }
    }
    LeaveCriticalSection(&b11_lock);
    if (host == NULL && kind < 0) {
        b11_host.stop("%08x is not a bridged Direct3D object (%s expected)", guest, b11_if[need].name);
    } else if (host == NULL) {
        b11_host.stop("%08x is bridged as %s where %s is expected", guest, b11_if[kind].name, b11_if[need].name);
    }
    return host;
}
static void *b11_host_of(uint32_t guest, int need) { return b11_lookup(guest, need, NULL); }

/* b11_lock held. */
static uint32_t b11_text_find(uint32_t owner, const char *s) {
    uint32_t i;
    for (i = 0u; i < b11_text_n; ++i) {
        if (b11_texts[i].owner == owner && strcmp(B11_GP(b11_texts[i].guest), s) == 0) {
            return b11_texts[i].guest;
        }
    }
    return 0u;
}

/* The guest's copy of a string that f, a reflection or a part of one, returned: the same address for the
 * same text, valid until the reflection goes. 0 for NULL, and after stopping when there is no memory. */
static uint32_t b11_text_of(const b11_found *f, const char *s) {
    const uint32_t owner = f->owner != 0u ? f->owner : f->serial;
    uint32_t g, fresh;
    size_t n;
    if (s == NULL) {
        return 0u;
    }
    EnterCriticalSection(&b11_lock);
    g = b11_text_find(owner, s);
    LeaveCriticalSection(&b11_lock);
    if (g != 0u) {
        return g;
    }
    n = strlen(s) + 1u;
    fresh = n <= 0x7fffffffu ? b11_host.galloc((uint32_t)n, 0) : 0u;
    if (fresh != 0u) {
        memcpy(B11_GP(fresh), s, n);
        EnterCriticalSection(&b11_lock);
        g = b11_text_find(owner, s);
        if (g == 0u && b11_alive(f)) {
            if (b11_text_n == b11_text_cap) {
                uint32_t cap = b11_text_cap != 0u ? b11_text_cap * 2u : 64u;
                b11_text *texts = realloc(b11_texts, cap * sizeof *texts);
                if (texts != NULL) {
                    b11_texts = texts;
                    b11_text_cap = cap;
                }
            }
            if (b11_text_n < b11_text_cap) {
                b11_texts[b11_text_n].owner = owner;
                b11_texts[b11_text_n++].guest = g = fresh;
                fresh = 0u;
            }
        }
        LeaveCriticalSection(&b11_lock);
        if (fresh != 0u) {
            b11_host.gfree(fresh);
        }
    }
    if (g == 0u) {
        b11_host.stop("no guest memory for a shader reflection string, or the reflection is gone");
    }
    return g;
}

/* ---- 4. argument conversion -------------------------------------------------------------------- */

#define B11_FN(I, N) static uint32_t m_##I##_##N(struct lift_ctx *c, const uint32_t *a)
/* The host interface behind a[0]. c is the runner's, passed along and not used. */
#define B11_SELF(T) \
    T *self = (T *)b11_host_of(a[0], K_##T); \
    (void)c; \
    if (self == NULL) { \
        return (uint32_t)E_FAIL; \
    }
#define B11_UNSUP(I, N, why) \
    B11_FN(I, N) { \
        (void)c; \
        (void)a; \
        b11_host.stop(#I "::" #N " is not bridged: " why); \
        return (uint32_t)E_NOTIMPL; \
    }

/* An interface pointer argument that may be null. */
static void *b11_arg(uint32_t guest, int need, int *bad) {
    void *host;
    if (guest == 0u) {
        return NULL;
    }
    host = b11_host_of(guest, need);
    if (host == NULL) {
        *bad = 1;
    }
    return host;
}

/* An array of n guest interface pointers -> host[]. A null array is left to the caller. */
static int b11_in_objs(uint32_t garr, uint32_t n, int kind, void **host) {
    uint32_t i;
    int bad = 0;
    if (garr == 0u) {
        return 1;
    }
    if (n > B11_MAX_PTRS) {
        b11_host.stop("an array of %u %s pointers is longer than any Direct3D 11 call takes", n, b11_if[kind].name);
        return 0;
    }
    for (i = 0u; i < n; ++i) {
        host[i] = b11_arg(b11_rd32(garr + 4u * i), kind, &bad);
    }
    return !bad;
}

/* Clears host[] for a call that fills in up to n interface pointers. */
static int b11_out_begin(uint32_t n, void **host) {
    if (n > B11_MAX_PTRS) {
        b11_host.stop("an array of %u interface pointers is longer than any Direct3D 11 call fills", n);
        return 0;
    }
    memset(host, 0, n * sizeof *host);
    return 1;
}

/* host[] -> an array of n guest interface pointers. */
static void b11_out_objs(uint32_t garr, uint32_t n, void **host, int kind) {
    uint32_t i;
    for (i = 0u; garr != 0u && i < n; ++i) {
        b11_wr32(garr + 4u * i, b11_wrap_out(host[i], kind));
    }
}

/* Stores the guest object for a returned interface pointer in the guest's out parameter. */
static uint32_t b11_out_obj(HRESULT hr, void *host, int kind, uint32_t gpp) {
    if (gpp != 0u) {
        b11_wr32(gpp, SUCCEEDED(hr) ? b11_wrap_out(host, kind) : 0u);
    }
    return (uint32_t)hr;
}

static void b11_guid_text(const GUID *g, char out[40]) {
    static const char hex[] = "0123456789abcdef";
    static const uint8_t order[16] = {3, 2, 1, 0, 5, 4, 7, 6, 8, 9, 10, 11, 12, 13, 14, 15};
    const uint8_t *p = (const uint8_t *)g;
    int i, n = 0;
    out[n++] = '{';
    for (i = 0; i < 16; ++i) {
        if (i == 4 || i == 6 || i == 8 || i == 10) {
            out[n++] = '-';
        }
        out[n++] = hex[p[order[i]] >> 4];
        out[n++] = hex[p[order[i]] & 15];
    }
    out[n++] = '}';
    out[n] = '\0';
}

/* The same for a method that returns whichever interface the caller names. */
static uint32_t b11_out_iid(HRESULT hr, void *host, uint32_t giid, uint32_t gpp, const char *what) {
    char text[40];
    int kind;
    if (gpp != 0u) {
        b11_wr32(gpp, 0u);
    }
    if (FAILED(hr) || host == NULL || gpp == 0u) {
        return (uint32_t)hr;
    }
    kind = b11_kind_of_iid(B11_GP(giid));
    if (kind < 0 || kind == K_Reflection) {
        IUnknown_Release((IUnknown *)host);
        b11_guid_text(B11_GP(giid), text);
        b11_host.stop("%s for interface %s succeeded on the host: this interface has no bridge", what, text);
        return (uint32_t)E_NOINTERFACE;
    }
    b11_wr32(gpp, b11_wrap_out(host, kind));
    return (uint32_t)hr;
}

/* The guest's SIZE_T is 32 bits: an amount of memory beyond it is reported as the largest value it holds. */
static uint32_t b11_size32(SIZE_T v) { return v > 0xffffffffu ? 0xffffffffu : (uint32_t)v; }

static FLOAT b11_float_arg(uint32_t bits) {
    FLOAT f;
    memcpy(&f, &bits, sizeof f);
    return f;
}

/* n D3D11_SUBRESOURCE_DATA of the guest as a host array (*heap, freed by the caller); NULL for none. */
static const D3D11_SUBRESOURCE_DATA *b11_sub_data(uint32_t g, uint64_t n, D3D11_SUBRESOURCE_DATA **heap) {
    const g32_D3D11_SUBRESOURCE_DATA *s = B11_GP(g);
    D3D11_SUBRESOURCE_DATA *d;
    uint32_t i;
    *heap = NULL;
    /* A description with more subresources than Direct3D 11 allows (2048 slices of 15 levels) is rejected by the host. */
    if (g == 0u || n == 0u || n > 65536u) {
        return NULL;
    }
    d = *heap = malloc((size_t)n * sizeof *d);
    if (d == NULL) {
        b11_host.stop("out of host memory for %u subresource descriptions", (uint32_t)n);
        return NULL;
    }
    for (i = 0u; i < n; ++i) {
        d[i].pSysMem = B11_GP(s[i].pSysMem);
        d[i].SysMemPitch = s[i].SysMemPitch;
        d[i].SysMemSlicePitch = s[i].SysMemSlicePitch;
    }
    return d;
}

/* Mip levels of a texture description; 0 asks for the full chain. */
static uint32_t b11_mip_levels(UINT levels, UINT w, UINT h, UINT d) {
    UINT big = w > h ? w : h, n = 1u;
    if (levels != 0u) {
        return levels;
    }
    for (big = big > d ? big : d; big > 1u; big >>= 1) {
        ++n;
    }
    return n;
}

static const DXGI_SWAP_CHAIN_DESC *b11_swap_desc_in(uint32_t g, DXGI_SWAP_CHAIN_DESC *d) {
    const g32_DXGI_SWAP_CHAIN_DESC *s = B11_GP(g);
    if (s == NULL) {
        return NULL;
    }
    d->BufferDesc = s->BufferDesc;
    d->SampleDesc = s->SampleDesc;
    d->BufferUsage = s->BufferUsage;
    d->BufferCount = s->BufferCount;
    d->OutputWindow = (HWND)B11_HND(s->OutputWindow);
    d->Windowed = s->Windowed;
    d->SwapEffect = s->SwapEffect;
    d->Flags = s->Flags;
    return d;
}

/* The fields DXGI_ADAPTER_DESC and DXGI_ADAPTER_DESC1 share. */
#define B11_ADAPTER_DESC_OUT(g, d) \
    do { \
        memcpy((g)->Description, (d).Description, sizeof (g)->Description); \
        (g)->VendorId = (d).VendorId; \
        (g)->DeviceId = (d).DeviceId; \
        (g)->SubSysId = (d).SubSysId; \
        (g)->Revision = (d).Revision; \
        (g)->DedicatedVideoMemory = b11_size32((d).DedicatedVideoMemory); \
        (g)->DedicatedSystemMemory = b11_size32((d).DedicatedSystemMemory); \
        (g)->SharedSystemMemory = b11_size32((d).SharedSystemMemory); \
        (g)->AdapterLuid = (d).AdapterLuid; \
    } while (0)

/* ---- 5. methods -------------------------------------------------------------------------------- */

/* ---- IUnknown, for every bridged interface ---- */

B11_FN(IUnknown, QueryInterface) {
    const GUID *iid = B11_P(1);
    void *out = NULL;
    b11_found f;
    HRESULT hr;
    IUnknown *self = b11_lookup(a[0], K_IUnknown, &f);
    (void)c;
    if (self == NULL) {
        return (uint32_t)E_FAIL;
    }
    if (iid == NULL || a[2] == 0u) {
        return (uint32_t)E_POINTER;
    }
    if (f.kind == K_Reflection && IsEqualGUID(iid, &b11_IID_ID3D11ShaderReflection_42)) {
        IUnknown_AddRef(self); /* the host object only knows the current IID */
        b11_wr32(a[2], a[0]);
        return (uint32_t)S_OK;
    }
    hr = IUnknown_QueryInterface(self, iid, &out);
    return b11_out_iid(hr, out, a[1], a[2], "QueryInterface");
}

B11_FN(IUnknown, AddRef) {
    B11_SELF(IUnknown)
    return IUnknown_AddRef(self);
}

B11_FN(IUnknown, Release) {
    b11_found f;
    ULONG left;
    IUnknown *self = b11_lookup(a[0], K_IUnknown, &f);
    (void)c;
    if (self == NULL) {
        return 0u;
    }
    left = IUnknown_Release(self);
    if (left == 0u) {
        /* An object with a notifier has already been retired by it if the host destroyed it, and stays
         * if the host still uses it. One without goes now. */
        EnterCriticalSection(&b11_lock);
        if (b11_obj[f.index].host == self && b11_obj[f.index].serial == f.serial && b11_obj[f.index].note == NULL) {
            b11_retire(&b11_obj[f.index]);
        }
        LeaveCriticalSection(&b11_lock);
        b11_drain();
    }
    return left;
}

/* Private data is bytes the host object stores: passed through. An interface cannot be stored: the host
 * object would call the guest's AddRef and Release. */
#define B11_PRIVATE_DATA(I) \
    B11_FN(I, SetPrivateData) { \
        B11_SELF(I) \
        return (uint32_t)I##_SetPrivateData(self, B11_P(1), a[2], B11_P(3)); \
    } \
    B11_FN(I, GetPrivateData) { \
        B11_SELF(I) \
        return (uint32_t)I##_GetPrivateData(self, B11_P(1), B11_P(2), B11_P(3)); \
    } \
    B11_FN(I, SetPrivateDataInterface) { \
        B11_SELF(I) \
        if (a[2] != 0u) { \
            b11_host.stop(#I "::SetPrivateDataInterface: a guest IUnknown (%08x) cannot be stored on a host object", a[2]); \
            return (uint32_t)E_NOTIMPL; \
        } \
        return (uint32_t)I##_SetPrivateDataInterface(self, B11_P(1), NULL); \
    }

/* ---- DXGI ---- */

B11_PRIVATE_DATA(IDXGIObject)

B11_FN(IDXGIObject, GetParent) {
    void *out = NULL;
    B11_SELF(IDXGIObject)
    const HRESULT hr = IDXGIObject_GetParent(self, B11_P(1), a[2] != 0u ? &out : NULL);
    return b11_out_iid(hr, out, a[1], a[2], "IDXGIObject::GetParent");
}

B11_FN(IDXGIDeviceSubObject, GetDevice) {
    void *out = NULL;
    B11_SELF(IDXGIDeviceSubObject)
    const HRESULT hr = IDXGIDeviceSubObject_GetDevice(self, B11_P(1), a[2] != 0u ? &out : NULL);
    return b11_out_iid(hr, out, a[1], a[2], "IDXGIDeviceSubObject::GetDevice");
}

B11_FN(IDXGIFactory, EnumAdapters) {
    IDXGIAdapter *out = NULL;
    B11_SELF(IDXGIFactory)
    const HRESULT hr = IDXGIFactory_EnumAdapters(self, a[1], a[2] != 0u ? &out : NULL);
    return b11_out_obj(hr, out, K_IDXGIAdapter, a[2]);
}

B11_FN(IDXGIFactory, MakeWindowAssociation) {
    B11_SELF(IDXGIFactory)
    return (uint32_t)IDXGIFactory_MakeWindowAssociation(self, (HWND)B11_HND(a[1]), a[2]);
}

B11_FN(IDXGIFactory, GetWindowAssociation) {
    HWND window = NULL;
    HRESULT hr;
    B11_SELF(IDXGIFactory)
    hr = IDXGIFactory_GetWindowAssociation(self, a[1] != 0u ? &window : NULL);
    if (a[1] != 0u) {
        b11_wr32(a[1], (uint32_t)(uintptr_t)window);
    }
    return (uint32_t)hr;
}

B11_FN(IDXGIFactory, CreateSwapChain) {
    DXGI_SWAP_CHAIN_DESC desc;
    IDXGISwapChain *out = NULL;
    IUnknown *device;
    int bad = 0;
    HRESULT hr;
    B11_SELF(IDXGIFactory)
    device = b11_arg(a[1], K_IUnknown, &bad);
    if (bad) {
        return (uint32_t)E_INVALIDARG;
    }
    hr = IDXGIFactory_CreateSwapChain(self, device, (DXGI_SWAP_CHAIN_DESC *)b11_swap_desc_in(a[2], &desc), a[3] != 0u ? &out : NULL);
    return b11_out_obj(hr, out, K_IDXGISwapChain, a[3]);
}

B11_UNSUP(IDXGIFactory, CreateSoftwareAdapter, "the module handle of a guest DLL is not a host rasterizer")

B11_FN(IDXGIFactory1, EnumAdapters1) {
    IDXGIAdapter1 *out = NULL;
    B11_SELF(IDXGIFactory1)
    const HRESULT hr = IDXGIFactory1_EnumAdapters1(self, a[1], a[2] != 0u ? &out : NULL);
    return b11_out_obj(hr, out, K_IDXGIAdapter1, a[2]);
}

B11_FN(IDXGIFactory1, IsCurrent) {
    B11_SELF(IDXGIFactory1)
    return (uint32_t)IDXGIFactory1_IsCurrent(self);
}

B11_FN(IDXGIAdapter, EnumOutputs) {
    IDXGIOutput *out = NULL;
    B11_SELF(IDXGIAdapter)
    const HRESULT hr = IDXGIAdapter_EnumOutputs(self, a[1], a[2] != 0u ? &out : NULL);
    return b11_out_obj(hr, out, K_IDXGIOutput, a[2]);
}

B11_FN(IDXGIAdapter, GetDesc) {
    g32_DXGI_ADAPTER_DESC *g = B11_P(1);
    DXGI_ADAPTER_DESC d;
    HRESULT hr;
    B11_SELF(IDXGIAdapter)
    hr = IDXGIAdapter_GetDesc(self, g != NULL ? &d : NULL);
    if (SUCCEEDED(hr) && g != NULL) {
        B11_ADAPTER_DESC_OUT(g, d);
    }
    return (uint32_t)hr;
}

B11_FN(IDXGIAdapter, CheckInterfaceSupport) {
    B11_SELF(IDXGIAdapter)
    return (uint32_t)IDXGIAdapter_CheckInterfaceSupport(self, B11_P(1), B11_P(2));
}

B11_FN(IDXGIAdapter1, GetDesc1) {
    g32_DXGI_ADAPTER_DESC1 *g = B11_P(1);
    DXGI_ADAPTER_DESC1 d;
    HRESULT hr;
    B11_SELF(IDXGIAdapter1)
    hr = IDXGIAdapter1_GetDesc1(self, g != NULL ? &d : NULL);
    if (SUCCEEDED(hr) && g != NULL) {
        B11_ADAPTER_DESC_OUT(g, d);
        g->Flags = d.Flags;
    }
    return (uint32_t)hr;
}

B11_FN(IDXGIOutput, GetDesc) {
    g32_DXGI_OUTPUT_DESC *g = B11_P(1);
    DXGI_OUTPUT_DESC d;
    HRESULT hr;
    B11_SELF(IDXGIOutput)
    hr = IDXGIOutput_GetDesc(self, g != NULL ? &d : NULL);
    if (SUCCEEDED(hr) && g != NULL) {
        memcpy(g->DeviceName, d.DeviceName, sizeof g->DeviceName);
        g->DesktopCoordinates = d.DesktopCoordinates;
        g->AttachedToDesktop = d.AttachedToDesktop;
        g->Rotation = d.Rotation;
        g->Monitor = (uint32_t)(uintptr_t)d.Monitor;
    }
    return (uint32_t)hr;
}

B11_FN(IDXGIOutput, GetDisplayModeList) {
    B11_SELF(IDXGIOutput)
    return (uint32_t)IDXGIOutput_GetDisplayModeList(self, (DXGI_FORMAT)a[1], a[2], B11_P(3), B11_P(4));
}

B11_FN(IDXGIOutput, FindClosestMatchingMode) {
    IUnknown *device;
    int bad = 0;
    B11_SELF(IDXGIOutput)
    device = b11_arg(a[3], K_IUnknown, &bad);
    if (bad) {
        return (uint32_t)E_INVALIDARG;
    }
    return (uint32_t)IDXGIOutput_FindClosestMatchingMode(self, B11_P(1), B11_P(2), device);
}

B11_FN(IDXGIOutput, WaitForVBlank) {
    B11_SELF(IDXGIOutput)
    return (uint32_t)IDXGIOutput_WaitForVBlank(self);
}

B11_FN(IDXGIOutput, TakeOwnership) {
    IUnknown *device;
    int bad = 0;
    B11_SELF(IDXGIOutput)
    device = b11_arg(a[1], K_IUnknown, &bad);
    if (bad) {
        return (uint32_t)E_INVALIDARG;
    }
    return (uint32_t)IDXGIOutput_TakeOwnership(self, device, (BOOL)a[2]);
}

B11_FN(IDXGIOutput, ReleaseOwnership) {
    B11_SELF(IDXGIOutput)
    IDXGIOutput_ReleaseOwnership(self);
    return 0u;
}

B11_FN(IDXGIOutput, GetGammaControlCapabilities) {
    B11_SELF(IDXGIOutput)
    return (uint32_t)IDXGIOutput_GetGammaControlCapabilities(self, B11_P(1));
}

B11_FN(IDXGIOutput, SetGammaControl) {
    B11_SELF(IDXGIOutput)
    return (uint32_t)IDXGIOutput_SetGammaControl(self, B11_P(1));
}

B11_FN(IDXGIOutput, GetGammaControl) {
    B11_SELF(IDXGIOutput)
    return (uint32_t)IDXGIOutput_GetGammaControl(self, B11_P(1));
}

B11_UNSUP(IDXGIOutput, SetDisplaySurface, "IDXGISurface has no bridge")
B11_UNSUP(IDXGIOutput, GetDisplaySurfaceData, "IDXGISurface has no bridge")

B11_FN(IDXGIOutput, GetFrameStatistics) {
    B11_SELF(IDXGIOutput)
    return (uint32_t)IDXGIOutput_GetFrameStatistics(self, B11_P(1));
}

B11_FN(IDXGISwapChain, Present) {
    B11_SELF(IDXGISwapChain)
    return (uint32_t)IDXGISwapChain_Present(self, a[1], a[2]);
}

B11_FN(IDXGISwapChain, GetBuffer) {
    void *out = NULL;
    B11_SELF(IDXGISwapChain)
    const HRESULT hr = IDXGISwapChain_GetBuffer(self, a[1], B11_P(2), a[3] != 0u ? &out : NULL);
    return b11_out_iid(hr, out, a[2], a[3], "IDXGISwapChain::GetBuffer");
}

B11_FN(IDXGISwapChain, SetFullscreenState) {
    IDXGIOutput *target;
    int bad = 0;
    B11_SELF(IDXGISwapChain)
    target = b11_arg(a[2], K_IDXGIOutput, &bad);
    if (bad) {
        return (uint32_t)E_INVALIDARG;
    }
    return (uint32_t)IDXGISwapChain_SetFullscreenState(self, (BOOL)a[1], target);
}

B11_FN(IDXGISwapChain, GetFullscreenState) {
    IDXGIOutput *target = NULL;
    B11_SELF(IDXGISwapChain)
    const HRESULT hr = IDXGISwapChain_GetFullscreenState(self, B11_P(1), a[2] != 0u ? &target : NULL);
    return b11_out_obj(hr, target, K_IDXGIOutput, a[2]);
}

B11_FN(IDXGISwapChain, GetDesc) {
    g32_DXGI_SWAP_CHAIN_DESC *g = B11_P(1);
    DXGI_SWAP_CHAIN_DESC d = {0};
    HRESULT hr;
    B11_SELF(IDXGISwapChain)
    hr = IDXGISwapChain_GetDesc(self, g != NULL ? &d : NULL);
    if (SUCCEEDED(hr) && g != NULL) {
        g->BufferDesc = d.BufferDesc;
        g->SampleDesc = d.SampleDesc;
        g->BufferUsage = d.BufferUsage;
        g->BufferCount = d.BufferCount;
        g->OutputWindow = (uint32_t)(uintptr_t)d.OutputWindow;
        g->Windowed = d.Windowed;
        g->SwapEffect = d.SwapEffect;
        g->Flags = d.Flags;
    }
    return (uint32_t)hr;
}

B11_FN(IDXGISwapChain, ResizeBuffers) {
    B11_SELF(IDXGISwapChain)
    return (uint32_t)IDXGISwapChain_ResizeBuffers(self, a[1], a[2], a[3], (DXGI_FORMAT)a[4], a[5]);
}

B11_FN(IDXGISwapChain, ResizeTarget) {
    B11_SELF(IDXGISwapChain)
    return (uint32_t)IDXGISwapChain_ResizeTarget(self, B11_P(1));
}

B11_FN(IDXGISwapChain, GetContainingOutput) {
    IDXGIOutput *out = NULL;
    B11_SELF(IDXGISwapChain)
    const HRESULT hr = IDXGISwapChain_GetContainingOutput(self, a[1] != 0u ? &out : NULL);
    return b11_out_obj(hr, out, K_IDXGIOutput, a[1]);
}

B11_FN(IDXGISwapChain, GetFrameStatistics) {
    B11_SELF(IDXGISwapChain)
    return (uint32_t)IDXGISwapChain_GetFrameStatistics(self, B11_P(1));
}

B11_FN(IDXGISwapChain, GetLastPresentCount) {
    B11_SELF(IDXGISwapChain)
    return (uint32_t)IDXGISwapChain_GetLastPresentCount(self, B11_P(1));
}

B11_FN(IDXGIDevice, GetAdapter) {
    IDXGIAdapter *out = NULL;
    B11_SELF(IDXGIDevice)
    const HRESULT hr = IDXGIDevice_GetAdapter(self, a[1] != 0u ? &out : NULL);
    return b11_out_obj(hr, out, K_IDXGIAdapter, a[1]);
}

B11_UNSUP(IDXGIDevice, CreateSurface, "IDXGISurface has no bridge")

B11_FN(IDXGIDevice, QueryResourceResidency) {
    IUnknown *res[B11_MAX_PTRS];
    B11_SELF(IDXGIDevice)
    if (!b11_in_objs(a[1], a[3], K_IUnknown, (void **)res)) {
        return (uint32_t)E_INVALIDARG;
    }
    return (uint32_t)IDXGIDevice_QueryResourceResidency(self, a[1] != 0u ? res : NULL, B11_P(2), a[3]);
}

B11_FN(IDXGIDevice, SetGPUThreadPriority) {
    B11_SELF(IDXGIDevice)
    return (uint32_t)IDXGIDevice_SetGPUThreadPriority(self, (INT)a[1]);
}

B11_FN(IDXGIDevice, GetGPUThreadPriority) {
    B11_SELF(IDXGIDevice)
    return (uint32_t)IDXGIDevice_GetGPUThreadPriority(self, B11_P(1));
}

B11_FN(IDXGIDevice1, SetMaximumFrameLatency) {
    B11_SELF(IDXGIDevice1)
    return (uint32_t)IDXGIDevice1_SetMaximumFrameLatency(self, a[1]);
}

B11_FN(IDXGIDevice1, GetMaximumFrameLatency) {
    B11_SELF(IDXGIDevice1)
    return (uint32_t)IDXGIDevice1_GetMaximumFrameLatency(self, B11_P(1));
}

/* ---- ID3D10Blob: the host buffer is out of the guest's reach, so the guest sees a copy made when the
 * blob was handed to it. ---- */

B11_FN(ID3D10Blob, GetBufferPointer) {
    b11_found f;
    (void)c;
    return b11_lookup(a[0], K_ID3D10Blob, &f) != NULL ? f.blob : 0u;
}

B11_FN(ID3D10Blob, GetBufferSize) {
    B11_SELF(ID3D10Blob)
    return (uint32_t)ID3D10Blob_GetBufferSize(self); /* at most 2 GiB: b11_wrap_out refused anything larger */
}

/* ---- Direct3D 11 device children ---- */

B11_PRIVATE_DATA(ID3D11DeviceChild)

B11_FN(ID3D11DeviceChild, GetDevice) {
    ID3D11Device *out = NULL;
    B11_SELF(ID3D11DeviceChild)
    ID3D11DeviceChild_GetDevice(self, a[1] != 0u ? &out : NULL);
    return b11_out_obj(S_OK, out, K_ID3D11Device, a[1]);
}

B11_FN(ID3D11Resource, GetType) {
    B11_SELF(ID3D11Resource)
    ID3D11Resource_GetType(self, B11_P(1));
    return 0u;
}

B11_FN(ID3D11Resource, SetEvictionPriority) {
    B11_SELF(ID3D11Resource)
    ID3D11Resource_SetEvictionPriority(self, a[1]);
    return 0u;
}

B11_FN(ID3D11Resource, GetEvictionPriority) {
    B11_SELF(ID3D11Resource)
    return ID3D11Resource_GetEvictionPriority(self);
}

/* A description without pointers: the host writes it straight into guest memory. */
#define B11_GET_DESC(I) \
    B11_FN(I, GetDesc) { \
        B11_SELF(I) \
        I##_GetDesc(self, B11_P(1)); \
        return 0u; \
    }
B11_GET_DESC(ID3D11Buffer)
B11_GET_DESC(ID3D11Texture1D)
B11_GET_DESC(ID3D11Texture2D)
B11_GET_DESC(ID3D11Texture3D)
B11_GET_DESC(ID3D11RenderTargetView)
B11_GET_DESC(ID3D11DepthStencilView)
B11_GET_DESC(ID3D11ShaderResourceView)
B11_GET_DESC(ID3D11UnorderedAccessView)
B11_GET_DESC(ID3D11SamplerState)
B11_GET_DESC(ID3D11RasterizerState)
B11_GET_DESC(ID3D11BlendState)
B11_GET_DESC(ID3D11DepthStencilState)
B11_GET_DESC(ID3D11Query)
B11_GET_DESC(ID3D11Counter)
B11_GET_DESC(ID3D11ClassInstance)

B11_FN(ID3D11View, GetResource) {
    ID3D11Resource *out = NULL;
    B11_SELF(ID3D11View)
    ID3D11View_GetResource(self, a[1] != 0u ? &out : NULL);
    return b11_out_obj(S_OK, out, K_ID3D11Resource, a[1]);
}

B11_FN(ID3D11Asynchronous, GetDataSize) {
    B11_SELF(ID3D11Asynchronous)
    return ID3D11Asynchronous_GetDataSize(self);
}

B11_FN(ID3D11ClassInstance, GetClassLinkage) {
    ID3D11ClassLinkage *out = NULL;
    B11_SELF(ID3D11ClassInstance)
    ID3D11ClassInstance_GetClassLinkage(self, a[1] != 0u ? &out : NULL);
    return b11_out_obj(S_OK, out, K_ID3D11ClassLinkage, a[1]);
}

/* The length is a SIZE_T the method reads and writes. */
#define B11_CLASS_NAME(N) \
    B11_FN(ID3D11ClassInstance, N) { \
        SIZE_T n = a[2] != 0u ? b11_rd32(a[2]) : 0u; \
        B11_SELF(ID3D11ClassInstance) \
        ID3D11ClassInstance_##N(self, B11_P(1), a[2] != 0u ? &n : NULL); \
        if (a[2] != 0u) { \
            b11_wr32(a[2], b11_size32(n)); \
        } \
        return 0u; \
    }
B11_CLASS_NAME(GetInstanceName)
B11_CLASS_NAME(GetTypeName)

B11_FN(ID3D11ClassLinkage, GetClassInstance) {
    ID3D11ClassInstance *out = NULL;
    B11_SELF(ID3D11ClassLinkage)
    const HRESULT hr = ID3D11ClassLinkage_GetClassInstance(self, B11_P(1), a[2], a[3] != 0u ? &out : NULL);
    return b11_out_obj(hr, out, K_ID3D11ClassInstance, a[3]);
}

B11_FN(ID3D11ClassLinkage, CreateClassInstance) {
    ID3D11ClassInstance *out = NULL;
    B11_SELF(ID3D11ClassLinkage)
    const HRESULT hr = ID3D11ClassLinkage_CreateClassInstance(self, B11_P(1), a[2], a[3], a[4], a[5], a[6] != 0u ? &out : NULL);
    return b11_out_obj(hr, out, K_ID3D11ClassInstance, a[6]);
}

B11_FN(ID3D11CommandList, GetContextFlags) {
    B11_SELF(ID3D11CommandList)
    return ID3D11CommandList_GetContextFlags(self);
}

/* ---- ID3D11Device ---- */

B11_FN(ID3D11Device, CreateBuffer) {
    const g32_D3D11_SUBRESOURCE_DATA *g = B11_P(2);
    D3D11_SUBRESOURCE_DATA init;
    ID3D11Buffer *out = NULL;
    HRESULT hr;
    B11_SELF(ID3D11Device)
    if (g != NULL) {
        init.pSysMem = B11_GP(g->pSysMem);
        init.SysMemPitch = g->SysMemPitch;
        init.SysMemSlicePitch = g->SysMemSlicePitch;
    }
    hr = ID3D11Device_CreateBuffer(self, B11_P(1), g != NULL ? &init : NULL, a[3] != 0u ? &out : NULL);
    return b11_out_obj(hr, out, K_ID3D11Buffer, a[3]);
}

/* Initial data is one D3D11_SUBRESOURCE_DATA per subresource of the description. */
B11_FN(ID3D11Device, CreateTexture1D) {
    const D3D11_TEXTURE1D_DESC *desc = B11_P(1);
    D3D11_SUBRESOURCE_DATA *heap = NULL;
    const D3D11_SUBRESOURCE_DATA *init = NULL;
    ID3D11Texture1D *out = NULL;
    HRESULT hr;
    B11_SELF(ID3D11Device)
    if (desc != NULL) {
        init = b11_sub_data(a[2], (uint64_t)b11_mip_levels(desc->MipLevels, desc->Width, 1u, 1u) * desc->ArraySize, &heap);
    }
    hr = ID3D11Device_CreateTexture1D(self, desc, init, a[3] != 0u ? &out : NULL);
    free(heap);
    return b11_out_obj(hr, out, K_ID3D11Texture1D, a[3]);
}

B11_FN(ID3D11Device, CreateTexture2D) {
    const D3D11_TEXTURE2D_DESC *desc = B11_P(1);
    D3D11_SUBRESOURCE_DATA *heap = NULL;
    const D3D11_SUBRESOURCE_DATA *init = NULL;
    ID3D11Texture2D *out = NULL;
    HRESULT hr;
    B11_SELF(ID3D11Device)
    if (desc != NULL) {
        init = b11_sub_data(a[2], (uint64_t)b11_mip_levels(desc->MipLevels, desc->Width, desc->Height, 1u) * desc->ArraySize, &heap);
    }
    hr = ID3D11Device_CreateTexture2D(self, desc, init, a[3] != 0u ? &out : NULL);
    free(heap);
    return b11_out_obj(hr, out, K_ID3D11Texture2D, a[3]);
}

B11_FN(ID3D11Device, CreateTexture3D) {
    const D3D11_TEXTURE3D_DESC *desc = B11_P(1);
    D3D11_SUBRESOURCE_DATA *heap = NULL;
    const D3D11_SUBRESOURCE_DATA *init = NULL;
    ID3D11Texture3D *out = NULL;
    HRESULT hr;
    B11_SELF(ID3D11Device)
    if (desc != NULL) {
        init = b11_sub_data(a[2], b11_mip_levels(desc->MipLevels, desc->Width, desc->Height, desc->Depth), &heap);
    }
    hr = ID3D11Device_CreateTexture3D(self, desc, init, a[3] != 0u ? &out : NULL);
    free(heap);
    return b11_out_obj(hr, out, K_ID3D11Texture3D, a[3]);
}

#define B11_CREATE_VIEW(N) \
    B11_FN(ID3D11Device, Create##N) { \
        ID3D11##N *out = NULL; \
        ID3D11Resource *res; \
        int bad = 0; \
        HRESULT hr; \
        B11_SELF(ID3D11Device) \
        res = b11_arg(a[1], K_ID3D11Resource, &bad); \
        if (bad) { \
            return (uint32_t)E_INVALIDARG; \
        } \
        hr = ID3D11Device_Create##N(self, res, B11_P(2), a[3] != 0u ? &out : NULL); \
        return b11_out_obj(hr, out, K_ID3D11##N, a[3]); \
    }
B11_CREATE_VIEW(ShaderResourceView)
B11_CREATE_VIEW(UnorderedAccessView)
B11_CREATE_VIEW(RenderTargetView)
B11_CREATE_VIEW(DepthStencilView)

B11_FN(ID3D11Device, CreateInputLayout) {
    const g32_D3D11_INPUT_ELEMENT_DESC *g = B11_P(1);
    D3D11_INPUT_ELEMENT_DESC *e = NULL;
    ID3D11InputLayout *out = NULL;
    UINT i, n = a[2];
    HRESULT hr;
    B11_SELF(ID3D11Device)
    if (g != NULL && n != 0u) {
        e = n <= 65536u ? malloc(n * sizeof *e) : NULL;
        if (e == NULL) {
            b11_host.stop("ID3D11Device::CreateInputLayout: no host memory for %u elements", n);
            return (uint32_t)E_OUTOFMEMORY;
        }
        for (i = 0u; i < n; ++i) {
            e[i].SemanticName = B11_GP(g[i].SemanticName);
            e[i].SemanticIndex = g[i].SemanticIndex;
            e[i].Format = g[i].Format;
            e[i].InputSlot = g[i].InputSlot;
            e[i].AlignedByteOffset = g[i].AlignedByteOffset;
            e[i].InputSlotClass = g[i].InputSlotClass;
            e[i].InstanceDataStepRate = g[i].InstanceDataStepRate;
        }
    }
    hr = ID3D11Device_CreateInputLayout(self, e, n, B11_P(3), a[4], a[5] != 0u ? &out : NULL); /* a[4]: SIZE_T, zero-extended */
    free(e);
    return b11_out_obj(hr, out, K_ID3D11InputLayout, a[5]);
}

/* (bytecode, SIZE_T length, class linkage, out) */
#define B11_CREATE_SHADER(N) \
    B11_FN(ID3D11Device, Create##N) { \
        ID3D11##N *out = NULL; \
        ID3D11ClassLinkage *linkage; \
        int bad = 0; \
        HRESULT hr; \
        B11_SELF(ID3D11Device) \
        linkage = b11_arg(a[3], K_ID3D11ClassLinkage, &bad); \
        if (bad) { \
            return (uint32_t)E_INVALIDARG; \
        } \
        hr = ID3D11Device_Create##N(self, B11_P(1), a[2], linkage, a[4] != 0u ? &out : NULL); \
        return b11_out_obj(hr, out, K_ID3D11##N, a[4]); \
    }
B11_CREATE_SHADER(VertexShader)
B11_CREATE_SHADER(GeometryShader)
B11_CREATE_SHADER(PixelShader)
B11_CREATE_SHADER(HullShader)
B11_CREATE_SHADER(DomainShader)
B11_CREATE_SHADER(ComputeShader)

B11_FN(ID3D11Device, CreateGeometryShaderWithStreamOutput) {
    const g32_D3D11_SO_DECLARATION_ENTRY *g = B11_P(3);
    D3D11_SO_DECLARATION_ENTRY *e = NULL;
    ID3D11GeometryShader *out = NULL;
    ID3D11ClassLinkage *linkage;
    UINT i, n = a[4];
    int bad = 0;
    HRESULT hr;
    B11_SELF(ID3D11Device)
    linkage = b11_arg(a[8], K_ID3D11ClassLinkage, &bad);
    if (bad) {
        return (uint32_t)E_INVALIDARG;
    }
    if (g != NULL && n != 0u) {
        e = n <= 65536u ? malloc(n * sizeof *e) : NULL;
        if (e == NULL) {
            b11_host.stop("ID3D11Device::CreateGeometryShaderWithStreamOutput: no host memory for %u entries", n);
            return (uint32_t)E_OUTOFMEMORY;
        }
        for (i = 0u; i < n; ++i) {
            e[i].Stream = g[i].Stream;
            e[i].SemanticName = B11_GP(g[i].SemanticName);
            e[i].SemanticIndex = g[i].SemanticIndex;
            e[i].StartComponent = g[i].StartComponent;
            e[i].ComponentCount = g[i].ComponentCount;
            e[i].OutputSlot = g[i].OutputSlot;
        }
    }
    hr = ID3D11Device_CreateGeometryShaderWithStreamOutput(self, B11_P(1), a[2], e, n, B11_P(5), a[6], a[7], linkage, a[9] != 0u ? &out : NULL);
    free(e);
    return b11_out_obj(hr, out, K_ID3D11GeometryShader, a[9]);
}

B11_FN(ID3D11Device, CreateClassLinkage) {
    ID3D11ClassLinkage *out = NULL;
    B11_SELF(ID3D11Device)
    const HRESULT hr = ID3D11Device_CreateClassLinkage(self, a[1] != 0u ? &out : NULL);
    return b11_out_obj(hr, out, K_ID3D11ClassLinkage, a[1]);
}

/* (description without pointers, out) */
#define B11_CREATE_FROM_DESC(N) \
    B11_FN(ID3D11Device, Create##N) { \
        ID3D11##N *out = NULL; \
        B11_SELF(ID3D11Device) \
        const HRESULT hr = ID3D11Device_Create##N(self, B11_P(1), a[2] != 0u ? &out : NULL); \
        return b11_out_obj(hr, out, K_ID3D11##N, a[2]); \
    }
B11_CREATE_FROM_DESC(BlendState)
B11_CREATE_FROM_DESC(DepthStencilState)
B11_CREATE_FROM_DESC(RasterizerState)
B11_CREATE_FROM_DESC(SamplerState)
B11_CREATE_FROM_DESC(Query)
B11_CREATE_FROM_DESC(Predicate)
B11_CREATE_FROM_DESC(Counter)

B11_FN(ID3D11Device, CreateDeferredContext) {
    ID3D11DeviceContext *out = NULL;
    B11_SELF(ID3D11Device)
    const HRESULT hr = ID3D11Device_CreateDeferredContext(self, a[1], a[2] != 0u ? &out : NULL);
    return b11_out_obj(hr, out, K_ID3D11DeviceContext, a[2]);
}

B11_FN(ID3D11Device, OpenSharedResource) {
    void *out = NULL;
    B11_SELF(ID3D11Device)
    const HRESULT hr = ID3D11Device_OpenSharedResource(self, (HANDLE)B11_HND(a[1]), B11_P(2), a[3] != 0u ? &out : NULL);
    return b11_out_iid(hr, out, a[2], a[3], "ID3D11Device::OpenSharedResource");
}

B11_FN(ID3D11Device, CheckFormatSupport) {
    B11_SELF(ID3D11Device)
    return (uint32_t)ID3D11Device_CheckFormatSupport(self, (DXGI_FORMAT)a[1], B11_P(2));
}

B11_FN(ID3D11Device, CheckMultisampleQualityLevels) {
    B11_SELF(ID3D11Device)
    return (uint32_t)ID3D11Device_CheckMultisampleQualityLevels(self, (DXGI_FORMAT)a[1], a[2], B11_P(3));
}

B11_FN(ID3D11Device, CheckCounterInfo) {
    B11_SELF(ID3D11Device)
    ID3D11Device_CheckCounterInfo(self, B11_P(1));
    return 0u;
}

B11_FN(ID3D11Device, CheckCounter) {
    B11_SELF(ID3D11Device)
    return (uint32_t)ID3D11Device_CheckCounter(self, B11_P(1), B11_P(2), B11_P(3), B11_P(4), B11_P(5), B11_P(6), B11_P(7), B11_P(8), B11_P(9));
}

/* The feature structures hold BOOLs, UINTs and enumerations only. */
B11_FN(ID3D11Device, CheckFeatureSupport) {
    B11_SELF(ID3D11Device)
    return (uint32_t)ID3D11Device_CheckFeatureSupport(self, (D3D11_FEATURE)a[1], B11_P(2), a[3]);
}

B11_PRIVATE_DATA(ID3D11Device)

B11_FN(ID3D11Device, GetFeatureLevel) {
    B11_SELF(ID3D11Device)
    return (uint32_t)ID3D11Device_GetFeatureLevel(self);
}

B11_FN(ID3D11Device, GetCreationFlags) {
    B11_SELF(ID3D11Device)
    return ID3D11Device_GetCreationFlags(self);
}

B11_FN(ID3D11Device, GetDeviceRemovedReason) {
    B11_SELF(ID3D11Device)
    return (uint32_t)ID3D11Device_GetDeviceRemovedReason(self);
}

B11_FN(ID3D11Device, GetImmediateContext) {
    ID3D11DeviceContext *out = NULL;
    B11_SELF(ID3D11Device)
    ID3D11Device_GetImmediateContext(self, a[1] != 0u ? &out : NULL);
    return b11_out_obj(S_OK, out, K_ID3D11DeviceContext, a[1]);
}

B11_FN(ID3D11Device, SetExceptionMode) {
    B11_SELF(ID3D11Device)
    return (uint32_t)ID3D11Device_SetExceptionMode(self, a[1]);
}

B11_FN(ID3D11Device, GetExceptionMode) {
    B11_SELF(ID3D11Device)
    return ID3D11Device_GetExceptionMode(self);
}

/* ---- ID3D11DeviceContext ---- */

/* Per-stage binding of arrays of interface pointers: (start slot, count, array). */
#define B11_STAGE_ARRAY(Stage, What, T) \
    B11_FN(ID3D11DeviceContext, Stage##Set##What) { \
        T *v[B11_MAX_PTRS]; \
        B11_SELF(ID3D11DeviceContext) \
        if (b11_in_objs(a[3], a[2], K_##T, (void **)v)) { \
            ID3D11DeviceContext_##Stage##Set##What(self, a[1], a[2], a[3] != 0u ? v : NULL); \
        } \
        return 0u; \
    } \
    B11_FN(ID3D11DeviceContext, Stage##Get##What) { \
        T *v[B11_MAX_PTRS]; \
        B11_SELF(ID3D11DeviceContext) \
        if (b11_out_begin(a[2], (void **)v)) { \
            ID3D11DeviceContext_##Stage##Get##What(self, a[1], a[2], a[3] != 0u ? v : NULL); \
            b11_out_objs(a[3], a[2], (void **)v, K_##T); \
        } \
        return 0u; \
    }

/* (shader, class instance array, count); the getter's count is the array's capacity going in. */
#define B11_STAGE_SHADER(Stage, T) \
    B11_FN(ID3D11DeviceContext, Stage##SetShader) { \
        ID3D11ClassInstance *ci[B11_MAX_PTRS]; \
        T *shader; \
        int bad = 0; \
        B11_SELF(ID3D11DeviceContext) \
        shader = b11_arg(a[1], K_##T, &bad); \
        if (!bad && b11_in_objs(a[2], a[3], K_ID3D11ClassInstance, (void **)ci)) { \
            ID3D11DeviceContext_##Stage##SetShader(self, shader, a[2] != 0u ? ci : NULL, a[3]); \
        } \
        return 0u; \
    } \
    B11_FN(ID3D11DeviceContext, Stage##GetShader) { \
        ID3D11ClassInstance *ci[B11_MAX_PTRS]; \
        T *shader = NULL; \
        UINT cap = a[2] != 0u && a[3] != 0u ? b11_rd32(a[3]) : 0u, n = cap; \
        B11_SELF(ID3D11DeviceContext) \
        if (b11_out_begin(cap, (void **)ci)) { \
            ID3D11DeviceContext_##Stage##GetShader(self, a[1] != 0u ? &shader : NULL, a[2] != 0u ? ci : NULL, a[3] != 0u ? &n : NULL); \
            b11_out_obj(S_OK, shader, K_##T, a[1]); \
            b11_out_objs(a[2], n < cap ? n : cap, (void **)ci, K_ID3D11ClassInstance); \
            if (a[3] != 0u) { \
                b11_wr32(a[3], n); \
            } \
        } \
        return 0u; \
    }

#define B11_STAGE(Stage, Shader) \
    B11_STAGE_ARRAY(Stage, ConstantBuffers, ID3D11Buffer) \
    B11_STAGE_ARRAY(Stage, ShaderResources, ID3D11ShaderResourceView) \
    B11_STAGE_ARRAY(Stage, Samplers, ID3D11SamplerState) \
    B11_STAGE_SHADER(Stage, Shader)
B11_STAGE(VS, ID3D11VertexShader)
B11_STAGE(PS, ID3D11PixelShader)
B11_STAGE(GS, ID3D11GeometryShader)
B11_STAGE(HS, ID3D11HullShader)
B11_STAGE(DS, ID3D11DomainShader)
B11_STAGE(CS, ID3D11ComputeShader)

/* A method of scalars only. */
#define B11_CTX_VOID(N, ...) \
    B11_FN(ID3D11DeviceContext, N) { \
        B11_SELF(ID3D11DeviceContext) \
        ID3D11DeviceContext_##N(self, __VA_ARGS__); \
        return 0u; \
    }
B11_CTX_VOID(DrawIndexed, a[1], a[2], (INT)a[3])
B11_CTX_VOID(Draw, a[1], a[2])
B11_CTX_VOID(DrawIndexedInstanced, a[1], a[2], a[3], (INT)a[4], a[5])
B11_CTX_VOID(DrawInstanced, a[1], a[2], a[3], a[4])
B11_CTX_VOID(IASetPrimitiveTopology, (D3D11_PRIMITIVE_TOPOLOGY)a[1])
B11_CTX_VOID(IAGetPrimitiveTopology, B11_P(1))
B11_CTX_VOID(Dispatch, a[1], a[2], a[3])
B11_CTX_VOID(RSSetViewports, a[1], B11_P(2))
B11_CTX_VOID(RSSetScissorRects, a[1], B11_P(2))
B11_CTX_VOID(RSGetViewports, B11_P(1), B11_P(2))
B11_CTX_VOID(RSGetScissorRects, B11_P(1), B11_P(2))

B11_FN(ID3D11DeviceContext, DrawAuto) {
    B11_SELF(ID3D11DeviceContext)
    ID3D11DeviceContext_DrawAuto(self);
    return 0u;
}

B11_FN(ID3D11DeviceContext, ClearState) {
    B11_SELF(ID3D11DeviceContext)
    ID3D11DeviceContext_ClearState(self);
    return 0u;
}

B11_FN(ID3D11DeviceContext, Flush) {
    B11_SELF(ID3D11DeviceContext)
    ID3D11DeviceContext_Flush(self);
    return 0u;
}

B11_FN(ID3D11DeviceContext, GetType) {
    B11_SELF(ID3D11DeviceContext)
    return (uint32_t)ID3D11DeviceContext_GetType(self);
}

B11_FN(ID3D11DeviceContext, GetContextFlags) {
    B11_SELF(ID3D11DeviceContext)
    return ID3D11DeviceContext_GetContextFlags(self);
}

/* A method whose a[1] is one interface pointer, followed by scalars or pointers into guest memory. */
#define B11_CTX_OBJ(N, T, ...) \
    B11_FN(ID3D11DeviceContext, N) { \
        T *obj; \
        int bad = 0; \
        B11_SELF(ID3D11DeviceContext) \
        obj = b11_arg(a[1], K_##T, &bad); \
        if (!bad) { \
            ID3D11DeviceContext_##N(self, obj, __VA_ARGS__); \
        } \
        return 0u; \
    }
B11_CTX_OBJ(IASetIndexBuffer, ID3D11Buffer, (DXGI_FORMAT)a[2], a[3])
B11_CTX_OBJ(SetPredication, ID3D11Predicate, (BOOL)a[2])
B11_CTX_OBJ(OMSetBlendState, ID3D11BlendState, B11_P(2), a[3])
B11_CTX_OBJ(OMSetDepthStencilState, ID3D11DepthStencilState, a[2])
B11_CTX_OBJ(DrawIndexedInstancedIndirect, ID3D11Buffer, a[2])
B11_CTX_OBJ(DrawInstancedIndirect, ID3D11Buffer, a[2])
B11_CTX_OBJ(DispatchIndirect, ID3D11Buffer, a[2])
B11_CTX_OBJ(UpdateSubresource, ID3D11Resource, a[2], B11_P(3), B11_P(4), a[5], a[6])
B11_CTX_OBJ(ClearRenderTargetView, ID3D11RenderTargetView, B11_P(2))
B11_CTX_OBJ(ClearUnorderedAccessViewUint, ID3D11UnorderedAccessView, B11_P(2))
B11_CTX_OBJ(ClearUnorderedAccessViewFloat, ID3D11UnorderedAccessView, B11_P(2))
B11_CTX_OBJ(ClearDepthStencilView, ID3D11DepthStencilView, a[2], b11_float_arg(a[3]), (UINT8)a[4])
B11_CTX_OBJ(SetResourceMinLOD, ID3D11Resource, b11_float_arg(a[2]))
B11_CTX_OBJ(ExecuteCommandList, ID3D11CommandList, (BOOL)a[2])

/* The same with nothing after the interface pointer. */
#define B11_CTX_OBJ0(N, T) \
    B11_FN(ID3D11DeviceContext, N) { \
        T *obj; \
        int bad = 0; \
        B11_SELF(ID3D11DeviceContext) \
        obj = b11_arg(a[1], K_##T, &bad); \
        if (!bad) { \
            ID3D11DeviceContext_##N(self, obj); \
        } \
        return 0u; \
    }
B11_CTX_OBJ0(IASetInputLayout, ID3D11InputLayout)
B11_CTX_OBJ0(Begin, ID3D11Asynchronous)
B11_CTX_OBJ0(End, ID3D11Asynchronous)
B11_CTX_OBJ0(RSSetState, ID3D11RasterizerState)
B11_CTX_OBJ0(GenerateMips, ID3D11ShaderResourceView)

/* FLOAT GetResourceMinLOD(ID3D11Resource *pResource). A 32-bit caller takes the result from x87 st(0) and
 * pops it; EAX means nothing. Only the host can put a value there. */
B11_FN(ID3D11DeviceContext, GetResourceMinLOD) {
    ID3D11Resource *res;
    int bad = 0;
    B11_SELF(ID3D11DeviceContext)
    res = b11_arg(a[1], K_ID3D11Resource, &bad);
    if (b11_host.return_float == NULL) {
        b11_host.stop("ID3D11DeviceContext::GetResourceMinLOD returns a FLOAT: it needs d3d11_bridge_host_t.return_float");
        return 0u;
    }
    b11_host.return_float(c, bad ? 0.0f : ID3D11DeviceContext_GetResourceMinLOD(self, res));
    return 0u;
}

B11_FN(ID3D11DeviceContext, GetData) {
    ID3D11Asynchronous *async;
    int bad = 0;
    B11_SELF(ID3D11DeviceContext)
    async = b11_arg(a[1], K_ID3D11Asynchronous, &bad);
    if (bad) {
        return (uint32_t)E_INVALIDARG;
    }
    return (uint32_t)ID3D11DeviceContext_GetData(self, async, B11_P(2), a[3], a[4]);
}

/* Map. The host maps the subresource wherever it likes, usually above 4 GiB, so the guest gets a shadow
 * block in guest memory with the same pitches. It is filled from the host mapping unless the map
 * discards the contents, and copied back at Unmap unless the map was read-only.
 * TODO: a WRITE_NO_OVERWRITE map of a large buffer copies the whole buffer both ways. */
typedef struct b11_mapping {
    struct b11_mapping *next;
    ID3D11DeviceContext *ctx;
    ID3D11Resource *res;
    UINT sub;
    uint32_t shadow;
    void *host;
    size_t size;
    int write;
} b11_mapping;
static b11_mapping *b11_maps;
static uint32_t b11_map_n;

static int b11_block_compressed(DXGI_FORMAT f) {
    return (f >= DXGI_FORMAT_BC1_TYPELESS && f <= DXGI_FORMAT_BC5_SNORM) || (f >= DXGI_FORMAT_BC6H_TYPELESS && f <= DXGI_FORMAT_BC7_UNORM_SRGB);
}

/* Formats whose mapping holds more than one plane: the rows of the description are not all of it. */
static int planar(DXGI_FORMAT f) {
    switch (f) {
    case DXGI_FORMAT_NV12:
    case DXGI_FORMAT_P010:
    case DXGI_FORMAT_P016:
    case DXGI_FORMAT_420_OPAQUE:
    case DXGI_FORMAT_NV11:
    case DXGI_FORMAT_P208:
    case DXGI_FORMAT_V208:
    case DXGI_FORMAT_V408:
        return 1;
    default:
        return 0;
    }
}

/* Bytes of a mapped subresource, from its description and the pitches the host reported. */
static int b11_map_size(ID3D11Resource *res, UINT sub, const D3D11_MAPPED_SUBRESOURCE *m, size_t *size) {
    D3D11_RESOURCE_DIMENSION dim = D3D11_RESOURCE_DIMENSION_UNKNOWN;
    ID3D11Resource_GetType(res, &dim);
    switch (dim) {
    case D3D11_RESOURCE_DIMENSION_BUFFER: {
        D3D11_BUFFER_DESC d;
        ID3D11Buffer_GetDesc((ID3D11Buffer *)res, &d);
        *size = d.ByteWidth;
        return 1;
    }
    case D3D11_RESOURCE_DIMENSION_TEXTURE1D:
        *size = m->RowPitch; /* one row */
        return m->RowPitch != 0u;
    case D3D11_RESOURCE_DIMENSION_TEXTURE2D: {
        D3D11_TEXTURE2D_DESC d;
        UINT rows;
        ID3D11Texture2D_GetDesc((ID3D11Texture2D *)res, &d);
        rows = d.Height >> (d.MipLevels != 0u ? sub % d.MipLevels : 0u);
        rows = rows != 0u ? rows : 1u;
        if (b11_block_compressed(d.Format)) {
            rows = (rows + 3u) / 4u; /* a row of the mapping is a row of 4x4 blocks */
        }
        *size = (size_t)m->RowPitch * rows;
        return m->RowPitch != 0u && !planar(d.Format);
    }
    case D3D11_RESOURCE_DIMENSION_TEXTURE3D: {
        D3D11_TEXTURE3D_DESC d;
        UINT depth;
        ID3D11Texture3D_GetDesc((ID3D11Texture3D *)res, &d);
        depth = d.Depth >> sub; /* a volume texture has one subresource per mip level */
        *size = (size_t)m->DepthPitch * (depth != 0u ? depth : 1u);
        return m->DepthPitch != 0u;
    }
    default:
        return 0;
    }
}

B11_FN(ID3D11DeviceContext, Map) {
    g32_D3D11_MAPPED_SUBRESOURCE *g = B11_P(5);
    D3D11_MAPPED_SUBRESOURCE m;
    ID3D11Resource *res;
    b11_mapping *map;
    size_t size = 0u;
    uint32_t shadow = 0u;
    int bad = 0;
    HRESULT hr;
    B11_SELF(ID3D11DeviceContext)
    res = b11_arg(a[1], K_ID3D11Resource, &bad);
    if (bad) {
        return (uint32_t)E_INVALIDARG;
    }
    memset(&m, 0, sizeof m);
    hr = ID3D11DeviceContext_Map(self, res, a[2], (D3D11_MAP)a[3], a[4], g != NULL ? &m : NULL);
    if (FAILED(hr) || g == NULL) {
        return (uint32_t)hr;
    }
    map = malloc(sizeof *map);
    if (map != NULL && b11_map_size(res, a[2], &m, &size) && size <= 0x7fffffffu) {
        shadow = b11_host.galloc(size != 0u ? (uint32_t)size : 1u, 0);
    }
    if (shadow == 0u) {
        free(map);
        ID3D11DeviceContext_Unmap(self, res, a[2]);
        b11_host.stop("ID3D11DeviceContext::Map: subresource %u (%u bytes a row, %u a slice) cannot be shadowed in guest memory", a[2],
                    m.RowPitch, m.DepthPitch);
        return (uint32_t)E_OUTOFMEMORY;
    }
    if (a[3] != D3D11_MAP_WRITE_DISCARD) {
        memcpy(B11_GP(shadow), m.pData, size);
    }
    map->ctx = self;
    map->res = res;
    map->sub = a[2];
    map->shadow = shadow;
    map->host = m.pData;
    map->size = size;
    map->write = a[3] != D3D11_MAP_READ;
    EnterCriticalSection(&b11_lock);
    map->next = b11_maps;
    b11_maps = map;
    ++b11_map_n;
    LeaveCriticalSection(&b11_lock);
    g->pData = shadow;
    g->RowPitch = m.RowPitch;
    g->DepthPitch = m.DepthPitch;
    return (uint32_t)hr;
}

B11_FN(ID3D11DeviceContext, Unmap) {
    ID3D11Resource *res;
    b11_mapping *map, **link;
    int bad = 0;
    B11_SELF(ID3D11DeviceContext)
    res = b11_arg(a[1], K_ID3D11Resource, &bad);
    if (bad) {
        return 0u;
    }
    EnterCriticalSection(&b11_lock);
    for (link = &b11_maps; (map = *link) != NULL; link = &map->next) {
        if (map->ctx == self && map->res == res && map->sub == a[2]) {
            *link = map->next;
            --b11_map_n;
            break;
        }
    }
    LeaveCriticalSection(&b11_lock);
    if (map != NULL) {
        if (map->write) {
            memcpy(map->host, B11_GP(map->shadow), map->size);
        }
        b11_host.gfree(map->shadow);
        free(map);
    }
    ID3D11DeviceContext_Unmap(self, res, a[2]);
    return 0u;
}

B11_FN(ID3D11DeviceContext, IASetVertexBuffers) {
    ID3D11Buffer *v[B11_MAX_PTRS];
    B11_SELF(ID3D11DeviceContext)
    if (b11_in_objs(a[3], a[2], K_ID3D11Buffer, (void **)v)) {
        ID3D11DeviceContext_IASetVertexBuffers(self, a[1], a[2], a[3] != 0u ? v : NULL, B11_P(4), B11_P(5));
    }
    return 0u;
}

B11_FN(ID3D11DeviceContext, IAGetVertexBuffers) {
    ID3D11Buffer *v[B11_MAX_PTRS];
    B11_SELF(ID3D11DeviceContext)
    if (b11_out_begin(a[2], (void **)v)) {
        ID3D11DeviceContext_IAGetVertexBuffers(self, a[1], a[2], a[3] != 0u ? v : NULL, B11_P(4), B11_P(5));
        b11_out_objs(a[3], a[2], (void **)v, K_ID3D11Buffer);
    }
    return 0u;
}

B11_FN(ID3D11DeviceContext, IAGetIndexBuffer) {
    ID3D11Buffer *out = NULL;
    B11_SELF(ID3D11DeviceContext)
    ID3D11DeviceContext_IAGetIndexBuffer(self, a[1] != 0u ? &out : NULL, B11_P(2), B11_P(3));
    return b11_out_obj(S_OK, out, K_ID3D11Buffer, a[1]);
}

B11_FN(ID3D11DeviceContext, IAGetInputLayout) {
    ID3D11InputLayout *out = NULL;
    B11_SELF(ID3D11DeviceContext)
    ID3D11DeviceContext_IAGetInputLayout(self, a[1] != 0u ? &out : NULL);
    return b11_out_obj(S_OK, out, K_ID3D11InputLayout, a[1]);
}

B11_FN(ID3D11DeviceContext, GetPredication) {
    ID3D11Predicate *out = NULL;
    B11_SELF(ID3D11DeviceContext)
    ID3D11DeviceContext_GetPredication(self, a[1] != 0u ? &out : NULL, B11_P(2));
    return b11_out_obj(S_OK, out, K_ID3D11Predicate, a[1]);
}

B11_FN(ID3D11DeviceContext, OMSetRenderTargets) {
    ID3D11RenderTargetView *rtv[B11_MAX_PTRS];
    ID3D11DepthStencilView *dsv;
    int bad = 0;
    B11_SELF(ID3D11DeviceContext)
    dsv = b11_arg(a[3], K_ID3D11DepthStencilView, &bad);
    if (!bad && b11_in_objs(a[2], a[1], K_ID3D11RenderTargetView, (void **)rtv)) {
        ID3D11DeviceContext_OMSetRenderTargets(self, a[1], a[2] != 0u ? rtv : NULL, dsv);
    }
    return 0u;
}

/* Either count may be the "keep what is bound" value, and then its array is not read. */
B11_FN(ID3D11DeviceContext, OMSetRenderTargetsAndUnorderedAccessViews) {
    ID3D11RenderTargetView *rtv[B11_MAX_PTRS];
    ID3D11UnorderedAccessView *uav[B11_MAX_PTRS];
    ID3D11DepthStencilView *dsv = NULL;
    int keep_rtv = a[1] == D3D11_KEEP_RENDER_TARGETS_AND_DEPTH_STENCIL, keep_uav = a[5] == D3D11_KEEP_UNORDERED_ACCESS_VIEWS;
    int bad = 0;
    B11_SELF(ID3D11DeviceContext)
    if (!keep_rtv) {
        dsv = b11_arg(a[3], K_ID3D11DepthStencilView, &bad);
        bad |= !b11_in_objs(a[2], a[1], K_ID3D11RenderTargetView, (void **)rtv);
    }
    if (!keep_uav) {
        bad |= !b11_in_objs(a[6], a[5], K_ID3D11UnorderedAccessView, (void **)uav);
    }
    if (!bad) {
        ID3D11DeviceContext_OMSetRenderTargetsAndUnorderedAccessViews(self, a[1], !keep_rtv && a[2] != 0u ? rtv : NULL, dsv, a[4], a[5],
                                                                     !keep_uav && a[6] != 0u ? uav : NULL, B11_P(7));
    }
    return 0u;
}

B11_FN(ID3D11DeviceContext, OMGetRenderTargets) {
    ID3D11RenderTargetView *rtv[B11_MAX_PTRS];
    ID3D11DepthStencilView *dsv = NULL;
    B11_SELF(ID3D11DeviceContext)
    if (b11_out_begin(a[1], (void **)rtv)) {
        ID3D11DeviceContext_OMGetRenderTargets(self, a[1], a[2] != 0u ? rtv : NULL, a[3] != 0u ? &dsv : NULL);
        b11_out_objs(a[2], a[1], (void **)rtv, K_ID3D11RenderTargetView);
        b11_out_obj(S_OK, dsv, K_ID3D11DepthStencilView, a[3]);
    }
    return 0u;
}

B11_FN(ID3D11DeviceContext, OMGetRenderTargetsAndUnorderedAccessViews) {
    ID3D11RenderTargetView *rtv[B11_MAX_PTRS];
    ID3D11UnorderedAccessView *uav[B11_MAX_PTRS];
    ID3D11DepthStencilView *dsv = NULL;
    B11_SELF(ID3D11DeviceContext)
    if (b11_out_begin(a[1], (void **)rtv) && b11_out_begin(a[5], (void **)uav)) {
        ID3D11DeviceContext_OMGetRenderTargetsAndUnorderedAccessViews(self, a[1], a[2] != 0u ? rtv : NULL, a[3] != 0u ? &dsv : NULL, a[4],
                                                                     a[5], a[6] != 0u ? uav : NULL);
        b11_out_objs(a[2], a[1], (void **)rtv, K_ID3D11RenderTargetView);
        b11_out_obj(S_OK, dsv, K_ID3D11DepthStencilView, a[3]);
        b11_out_objs(a[6], a[5], (void **)uav, K_ID3D11UnorderedAccessView);
    }
    return 0u;
}

B11_FN(ID3D11DeviceContext, OMGetBlendState) {
    ID3D11BlendState *out = NULL;
    B11_SELF(ID3D11DeviceContext)
    ID3D11DeviceContext_OMGetBlendState(self, a[1] != 0u ? &out : NULL, B11_P(2), B11_P(3));
    return b11_out_obj(S_OK, out, K_ID3D11BlendState, a[1]);
}

B11_FN(ID3D11DeviceContext, OMGetDepthStencilState) {
    ID3D11DepthStencilState *out = NULL;
    B11_SELF(ID3D11DeviceContext)
    ID3D11DeviceContext_OMGetDepthStencilState(self, a[1] != 0u ? &out : NULL, B11_P(2));
    return b11_out_obj(S_OK, out, K_ID3D11DepthStencilState, a[1]);
}

B11_FN(ID3D11DeviceContext, RSGetState) {
    ID3D11RasterizerState *out = NULL;
    B11_SELF(ID3D11DeviceContext)
    ID3D11DeviceContext_RSGetState(self, a[1] != 0u ? &out : NULL);
    return b11_out_obj(S_OK, out, K_ID3D11RasterizerState, a[1]);
}

B11_FN(ID3D11DeviceContext, SOSetTargets) {
    ID3D11Buffer *v[B11_MAX_PTRS];
    B11_SELF(ID3D11DeviceContext)
    if (b11_in_objs(a[2], a[1], K_ID3D11Buffer, (void **)v)) {
        ID3D11DeviceContext_SOSetTargets(self, a[1], a[2] != 0u ? v : NULL, B11_P(3));
    }
    return 0u;
}

B11_FN(ID3D11DeviceContext, SOGetTargets) {
    ID3D11Buffer *v[B11_MAX_PTRS];
    B11_SELF(ID3D11DeviceContext)
    if (b11_out_begin(a[1], (void **)v)) {
        ID3D11DeviceContext_SOGetTargets(self, a[1], a[2] != 0u ? v : NULL);
        b11_out_objs(a[2], a[1], (void **)v, K_ID3D11Buffer);
    }
    return 0u;
}

B11_FN(ID3D11DeviceContext, CSSetUnorderedAccessViews) {
    ID3D11UnorderedAccessView *v[B11_MAX_PTRS];
    B11_SELF(ID3D11DeviceContext)
    if (b11_in_objs(a[3], a[2], K_ID3D11UnorderedAccessView, (void **)v)) {
        ID3D11DeviceContext_CSSetUnorderedAccessViews(self, a[1], a[2], a[3] != 0u ? v : NULL, B11_P(4));
    }
    return 0u;
}

B11_FN(ID3D11DeviceContext, CSGetUnorderedAccessViews) {
    ID3D11UnorderedAccessView *v[B11_MAX_PTRS];
    B11_SELF(ID3D11DeviceContext)
    if (b11_out_begin(a[2], (void **)v)) {
        ID3D11DeviceContext_CSGetUnorderedAccessViews(self, a[1], a[2], a[3] != 0u ? v : NULL);
        b11_out_objs(a[3], a[2], (void **)v, K_ID3D11UnorderedAccessView);
    }
    return 0u;
}

B11_FN(ID3D11DeviceContext, CopySubresourceRegion) {
    ID3D11Resource *dst, *src;
    int bad = 0;
    B11_SELF(ID3D11DeviceContext)
    dst = b11_arg(a[1], K_ID3D11Resource, &bad);
    src = b11_arg(a[6], K_ID3D11Resource, &bad);
    if (!bad) {
        ID3D11DeviceContext_CopySubresourceRegion(self, dst, a[2], a[3], a[4], a[5], src, a[7], B11_P(8));
    }
    return 0u;
}

B11_FN(ID3D11DeviceContext, CopyResource) {
    ID3D11Resource *dst, *src;
    int bad = 0;
    B11_SELF(ID3D11DeviceContext)
    dst = b11_arg(a[1], K_ID3D11Resource, &bad);
    src = b11_arg(a[2], K_ID3D11Resource, &bad);
    if (!bad) {
        ID3D11DeviceContext_CopyResource(self, dst, src);
    }
    return 0u;
}

B11_FN(ID3D11DeviceContext, CopyStructureCount) {
    ID3D11Buffer *dst;
    ID3D11UnorderedAccessView *src;
    int bad = 0;
    B11_SELF(ID3D11DeviceContext)
    dst = b11_arg(a[1], K_ID3D11Buffer, &bad);
    src = b11_arg(a[3], K_ID3D11UnorderedAccessView, &bad);
    if (!bad) {
        ID3D11DeviceContext_CopyStructureCount(self, dst, a[2], src);
    }
    return 0u;
}

B11_FN(ID3D11DeviceContext, ResolveSubresource) {
    ID3D11Resource *dst, *src;
    int bad = 0;
    B11_SELF(ID3D11DeviceContext)
    dst = b11_arg(a[1], K_ID3D11Resource, &bad);
    src = b11_arg(a[3], K_ID3D11Resource, &bad);
    if (!bad) {
        ID3D11DeviceContext_ResolveSubresource(self, dst, a[2], src, a[4], (DXGI_FORMAT)a[5]);
    }
    return 0u;
}

B11_FN(ID3D11DeviceContext, FinishCommandList) {
    ID3D11CommandList *out = NULL;
    B11_SELF(ID3D11DeviceContext)
    const HRESULT hr = ID3D11DeviceContext_FinishCommandList(self, (BOOL)a[1], a[2] != 0u ? &out : NULL);
    return b11_out_obj(hr, out, K_ID3D11CommandList, a[2]);
}

/* ---- D3DCompiler_42's ID3D11ShaderReflection: the three methods the game calls (see B11_REFLECTION_SLOTS) ----
 * The host object is d3dcompiler_47's. Its strings are host memory: the guest gets copies that last as
 * long as the reflection, as the originals do. */

/* Slot 4. ID3D11ShaderReflectionConstantBuffer *GetConstantBufferByIndex(UINT Index)
 * The buffer belongs to the reflection: the same pointer for the same index, and no reference to count. */
static uint32_t m_Reflection_slot4(struct lift_ctx *c, const uint32_t *a) {
    b11_found f;
    ID3D11ShaderReflection *self = b11_lookup(a[0], K_Reflection, &f);
    (void)c;
    if (self == NULL) {
        return 0u;
    }
    return b11_wrap_part(self->lpVtbl->GetConstantBufferByIndex(self, a[1]), K_ReflectionCB, &f);
}

/* Slot 6. HRESULT GetResourceBindingDesc(UINT ResourceIndex, D3D11_SHADER_INPUT_BIND_DESC *pDesc) */
static uint32_t m_Reflection_slot6(struct lift_ctx *c, const uint32_t *a) {
    b11_found f;
    D3D11_SHADER_INPUT_BIND_DESC d = {0};
    g32_D3D11_SHADER_INPUT_BIND_DESC *g = B11_P(2);
    HRESULT hr;
    ID3D11ShaderReflection *self = b11_lookup(a[0], K_Reflection, &f);
    (void)c;
    if (self == NULL) {
        return (uint32_t)E_FAIL;
    }
    hr = self->lpVtbl->GetResourceBindingDesc(self, a[1], g != NULL ? &d : NULL);
    if (SUCCEEDED(hr) && g != NULL) {
        const uint32_t name = b11_text_of(&f, d.Name);
        if (name == 0u && d.Name != NULL) {
            return (uint32_t)E_OUTOFMEMORY;
        }
        g->Name = name;
        g->Type = d.Type;
        g->BindPoint = d.BindPoint;
        g->BindCount = d.BindCount;
        g->uFlags = d.uFlags;
        g->ReturnType = d.ReturnType;
        g->Dimension = d.Dimension;
        g->NumSamples = d.NumSamples;
    }
    return (uint32_t)hr;
}

/* Slot 0 of a constant buffer. HRESULT GetDesc(D3D11_SHADER_BUFFER_DESC *pDesc) */
static uint32_t m_ReflectionCB_slot0(struct lift_ctx *c, const uint32_t *a) {
    b11_found f;
    D3D11_SHADER_BUFFER_DESC d = {0};
    g32_D3D11_SHADER_BUFFER_DESC *g = B11_P(1);
    HRESULT hr;
    ID3D11ShaderReflectionConstantBuffer *self = b11_lookup(a[0], K_ReflectionCB, &f);
    (void)c;
    if (self == NULL) {
        return (uint32_t)E_FAIL;
    }
    hr = self->lpVtbl->GetDesc(self, g != NULL ? &d : NULL);
    if (SUCCEEDED(hr) && g != NULL) {
        const uint32_t name = b11_text_of(&f, d.Name);
        if (name == 0u && d.Name != NULL) {
            return (uint32_t)E_OUTOFMEMORY;
        }
        g->Name = name;
        g->Type = d.Type;
        g->Variables = d.Variables;
        g->Size = d.Size;
        g->uFlags = d.uFlags;
    }
    return (uint32_t)hr;
}

/* The slots the game does not call: what they are in D3DCompiler_42 is not known. */
#define B11_AS_REFLECTION_STUB(I, n) \
    static uint32_t m_##I##_slot##n(struct lift_ctx *c, const uint32_t *a) { \
        (void)c; \
        (void)a; \
        b11_host.stop("D3DCompiler_42 shader reflection: vtable slot " #n " of " #I " was called, which is not bridged"); \
        return (uint32_t)E_NOTIMPL; \
    }
B11_REFLECTION_UNKNOWN(B11_AS_REFLECTION_STUB)

/* ---- 6. development aids and entry points ---------------------------------------------------------
 * Two aids, both off unless the environment asks; d3d11_bridge_init reads it once.
 *
 *   ROME2_D3D11_TRACE=<file>  One line for every call the guest makes into the bridge, written when the call
 *                             returns: thread (numbered by first call), name, arguments, result. Values that
 *                             belong to one run are left out: an address is * (0 when null), a handle h, This
 *                             is not shown. What stays (values, GUIDs, strings, results) is the same in any
 *                             run that makes the same calls, so two records can be compared line by line.
 *   ROME2_D3D11_DEBUG=1       Devices are created with D3D11_CREATE_DEVICE_DEBUG, and what Direct3D's debug
 *                             layer says about a call (corruption, errors, warnings) is printed on stderr
 *                             when the call returns: the host checks every converted argument.
 *   ROME2_D3D11_DEBUG=stop    The same, and the first error or corruption message stops the run.
 *
 * The debug layer is the Windows optional feature "Graphics Tools". Without it no debug device can be
 * created, and the run stops there saying so. A message is attributed to the call that was returning when
 * it was read; with several threads inside Direct3D that can be a neighbour's. */

#define B11_DEV_TRACE 1u
#define B11_DEV_DEBUG 2u
#define B11_DEV_STOP 4u
static uint32_t b11_dev; /* nonzero: every call ends in b11_after */
static FILE *b11_trace;
static IDXGIInfoQueue *b11_info;
static CRITICAL_SECTION b11_dev_lock; /* one line, or one reading of the message queue, at a time */
static volatile LONG b11_threads;
static __declspec(thread) uint32_t b11_thread_no;

static void b11_dev_init(void) {
    typedef HRESULT(WINAPI * get_interface)(REFIID, void **);
    const char *path = getenv("ROME2_D3D11_TRACE"), *debug = getenv("ROME2_D3D11_DEBUG");
    InitializeCriticalSection(&b11_dev_lock);
    if (path != NULL && path[0] != '\0') {
        b11_trace = fopen(path, "wb"); /* the same bytes on any host */
        if (b11_trace == NULL) {
            b11_host.stop("ROME2_D3D11_TRACE: cannot write %s", path);
        } else {
            b11_dev |= B11_DEV_TRACE;
        }
    }
    if (debug != NULL && debug[0] != '\0' && strcmp(debug, "0") != 0) {
        const HMODULE lib = LoadLibraryExW(L"dxgidebug.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
        const get_interface get = lib != NULL ? (get_interface)(uintptr_t)GetProcAddress(lib, "DXGIGetDebugInterface") : NULL;
        b11_dev |= B11_DEV_DEBUG | (strcmp(debug, "stop") == 0 ? B11_DEV_STOP : 0u);
        if (get == NULL || FAILED(get(&IID_IDXGIInfoQueue, (void **)&b11_info))) {
            b11_info = NULL; /* no debug layer: creating the device will say so */
        }
    }
}

/* The creation flags of a device, and the one failure ROME2_D3D11_DEBUG can cause. */
#define B11_DEVICE_FLAGS(flags) ((flags) | ((b11_dev & B11_DEV_DEBUG) != 0u ? (UINT)D3D11_CREATE_DEVICE_DEBUG : 0u))
static void b11_debug_created(HRESULT hr, const char *what) {
    if (hr == DXGI_ERROR_SDK_COMPONENT_MISSING && (b11_dev & B11_DEV_DEBUG) != 0u) {
        b11_host.stop("%s: ROME2_D3D11_DEBUG is set and Direct3D's debug layer is not installed (the Windows optional feature "
                      "\"Graphics Tools\")", what);
    }
}

static void b11_trace_call(const char *name, const char *sig, char ret, const uint32_t *a, uint32_t r) {
    char line[768];
    size_t n, i, k;
    if (b11_thread_no == 0u) {
        b11_thread_no = (uint32_t)InterlockedIncrement(&b11_threads);
    }
    n = (size_t)snprintf(line, sizeof line, "%u %s(", b11_thread_no, name);
    for (i = 0u; sig[i] != '\0' && n < sizeof line - 96u; ++i) {
        const uint32_t v = a[i];
        if (sig[i] == 't') {
            continue;
        }
        if (line[n - 1u] != '(') {
            line[n++] = ' ';
        }
        if (sig[i] == 'v') {
            n += (size_t)snprintf(line + n, sizeof line - n, "%x", v);
        } else if (sig[i] == 'g' && v != 0u) {
            const GUID *g = B11_GP(v);
            n += (size_t)snprintf(line + n, sizeof line - n, "{%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}", (unsigned long)g->Data1,
                                  g->Data2, g->Data3, g->Data4[0], g->Data4[1], g->Data4[2], g->Data4[3], g->Data4[4], g->Data4[5],
                                  g->Data4[6], g->Data4[7]);
        } else if (sig[i] == 's' && v != 0u) {
            const char *s = B11_GP(v);
            line[n++] = '"';
            for (k = 0u; k < 64u && s[k] != '\0'; ++k) {
                line[n++] = s[k] >= ' ' && s[k] <= '~' && s[k] != '"' ? s[k] : '?';
            }
            line[n++] = '"';
        } else {
            line[n++] = v == 0u ? '0' : sig[i] == 'h' ? 'h' : '*';
        }
    }
    if (ret == 'D' || ret == 'Z') {
        n += (size_t)snprintf(line + n, sizeof line - n, ") = %x\n", r);
    } else {
        n += (size_t)snprintf(line + n, sizeof line - n, ret == 'P' ? r != 0u ? ") = *\n" : ") = 0\n" : ")\n");
    }
    EnterCriticalSection(&b11_dev_lock);
    fwrite(line, 1u, n, b11_trace);
    fflush(b11_trace); /* the run may end without the C runtime's leave */
    LeaveCriticalSection(&b11_dev_lock);
}

static void b11_debug_read(const char *name) {
    static const char *const severity[] = {"corruption", "error", "warning"};
    char first[512];
    int fatal = 0;
    UINT64 i, n;
    EnterCriticalSection(&b11_dev_lock);
    n = IDXGIInfoQueue_GetNumStoredMessages(b11_info, DXGI_DEBUG_ALL);
    for (i = 0u; i < n; ++i) {
        SIZE_T size = 0u;
        DXGI_INFO_QUEUE_MESSAGE *m;
        if (FAILED(IDXGIInfoQueue_GetMessage(b11_info, DXGI_DEBUG_ALL, i, NULL, &size)) || (m = malloc(size)) == NULL) {
            continue;
        }
        if (SUCCEEDED(IDXGIInfoQueue_GetMessage(b11_info, DXGI_DEBUG_ALL, i, m, &size))
            && m->Severity <= DXGI_INFO_QUEUE_MESSAGE_SEVERITY_WARNING) {
            fprintf(stderr, "d3d11 debug layer, %s: %s: %s\n", name, severity[m->Severity], m->pDescription);
            if (m->Severity <= DXGI_INFO_QUEUE_MESSAGE_SEVERITY_ERROR && !fatal) {
                fatal = 1;
                snprintf(first, sizeof first, "%s", m->pDescription);
            }
        }
        free(m);
    }
    if (n != 0u) {
        IDXGIInfoQueue_ClearStoredMessages(b11_info, DXGI_DEBUG_ALL);
    }
    LeaveCriticalSection(&b11_dev_lock);
    if (fatal && (b11_dev & B11_DEV_STOP) != 0u) {
        b11_host.stop("Direct3D's debug layer, at %s: %s", name, first);
    }
}

/* The end of every call from the guest while an aid is on. a still holds the arguments: no bridge function
 * writes to them. */
static void b11_after(const char *name, const char *sig, char ret, const uint32_t *a, uint32_t r) {
    if (b11_trace != NULL) {
        b11_trace_call(name, sig, ret, a, r);
    }
    if (b11_info != NULL) {
        b11_debug_read(name);
    }
}

/* Inside live_main.c nobody calls d3d11_bridge_init: the first entry does. */
#ifdef D3D11_BRIDGE_LIVE
static void b11_live_init(void);
#define B11_ENSURE() b11_live_init()
#else
#define B11_ENSURE() ((void)0)
#endif

void d3d11_bridge_init(const d3d11_bridge_host_t *host) {
    static int ready;
    b11_host = *host;
    if (!ready) {
        InitializeCriticalSection(&b11_lock);
        b11_dev_init();
        ready = 1;
    }
}

void *d3d11_bridge_host_object(uint32_t guest) {
    b11_object *o;
    void *host;
    B11_ENSURE();
    EnterCriticalSection(&b11_lock);
    o = b11_object_at(guest);
    host = o != NULL ? o->host : NULL;
    LeaveCriticalSection(&b11_lock);
    return host;
}

uint32_t d3d11_bridge_wrap(void *host_iface, const void *iid) {
    int kind = b11_kind_of_iid(iid);
    B11_ENSURE();
    return kind >= 0 ? b11_wrap_out(host_iface, kind) : 0u;
}

uint32_t d3d11_bridge_live_objects(void) { return b11_obj_live; }
uint32_t d3d11_bridge_live_maps(void) { return b11_map_n; }

#define B11_AS_EXPORT(dll, name, nargs, sig) {dll, #name, nargs, d3d11_bridge_##name},

/* HRESULT CreateDXGIFactory(REFIID riid, void **ppFactory) */
static uint32_t b11_x_CreateDXGIFactory(struct lift_ctx *c, const uint32_t *a) {
    (void)c;
    void *out = NULL;
    const HRESULT hr = CreateDXGIFactory(B11_P(0), a[1] != 0u ? &out : NULL);
    return b11_out_iid(hr, out, a[0], a[1], "CreateDXGIFactory");
}

static uint32_t b11_x_CreateDXGIFactory1(struct lift_ctx *c, const uint32_t *a) {
    (void)c;
    void *out = NULL;
    const HRESULT hr = CreateDXGIFactory1(B11_P(0), a[1] != 0u ? &out : NULL);
    return b11_out_iid(hr, out, a[0], a[1], "CreateDXGIFactory1");
}

/* HRESULT D3D11CreateDevice(IDXGIAdapter *pAdapter, D3D_DRIVER_TYPE DriverType, HMODULE Software, UINT Flags,
 *     const D3D_FEATURE_LEVEL *pFeatureLevels, UINT FeatureLevels, UINT SDKVersion, ID3D11Device **ppDevice,
 *     D3D_FEATURE_LEVEL *pFeatureLevel, ID3D11DeviceContext **ppImmediateContext) */
static uint32_t b11_x_D3D11CreateDevice(struct lift_ctx *c, const uint32_t *a) {
    (void)c;
    ID3D11Device *device = NULL;
    ID3D11DeviceContext *context = NULL;
    IDXGIAdapter *adapter;
    int bad = 0;
    HRESULT hr;
    adapter = b11_arg(a[0], K_IDXGIAdapter, &bad);
    if (bad) {
        return (uint32_t)E_INVALIDARG;
    }
    if (a[2] != 0u) {
        b11_host.stop("D3D11CreateDevice: the software rasterizer module %08x is a guest DLL", a[2]);
        return (uint32_t)E_INVALIDARG;
    }
    hr = D3D11CreateDevice(adapter, (D3D_DRIVER_TYPE)a[1], NULL, B11_DEVICE_FLAGS(a[3]), B11_P(4), a[5], a[6],
                           a[7] != 0u ? &device : NULL, B11_P(8), a[9] != 0u ? &context : NULL);
    b11_debug_created(hr, "D3D11CreateDevice");
    b11_out_obj(hr, device, K_ID3D11Device, a[7]);
    return b11_out_obj(hr, context, K_ID3D11DeviceContext, a[9]);
}

/* The same with (const DXGI_SWAP_CHAIN_DESC *pSwapChainDesc, IDXGISwapChain **ppSwapChain) before ppDevice. */
static uint32_t b11_x_D3D11CreateDeviceAndSwapChain(struct lift_ctx *c, const uint32_t *a) {
    (void)c;
    DXGI_SWAP_CHAIN_DESC desc;
    IDXGISwapChain *swap = NULL;
    ID3D11Device *device = NULL;
    ID3D11DeviceContext *context = NULL;
    IDXGIAdapter *adapter;
    int bad = 0;
    HRESULT hr;
    adapter = b11_arg(a[0], K_IDXGIAdapter, &bad);
    if (bad) {
        return (uint32_t)E_INVALIDARG;
    }
    if (a[2] != 0u) {
        b11_host.stop("D3D11CreateDeviceAndSwapChain: the software rasterizer module %08x is a guest DLL", a[2]);
        return (uint32_t)E_INVALIDARG;
    }
    hr = D3D11CreateDeviceAndSwapChain(adapter, (D3D_DRIVER_TYPE)a[1], NULL, B11_DEVICE_FLAGS(a[3]), B11_P(4), a[5], a[6],
                                       b11_swap_desc_in(a[7], &desc), a[8] != 0u ? &swap : NULL, a[9] != 0u ? &device : NULL, B11_P(10),
                                       a[11] != 0u ? &context : NULL);
    b11_debug_created(hr, "D3D11CreateDeviceAndSwapChain");
    b11_out_obj(hr, swap, K_IDXGISwapChain, a[8]);
    b11_out_obj(hr, device, K_ID3D11Device, a[9]);
    return b11_out_obj(hr, context, K_ID3D11DeviceContext, a[11]);
}

/* ID3DInclude the guest implements, as the host compiler sees it. The guest object is one dword, the
 * address of a vtable of two stdcall functions that take the object as their first stack argument. */
typedef struct b11_include_adapter {
    ID3DInclude base;
    struct lift_ctx *c; /* of the compile call: the compiler calls back on that thread, inside it */
    uint32_t guest;
    const void *host_parent; /* the one including file that is not in guest memory, and what the guest is */
    uint32_t parent_token;   /* given for it */
} b11_include_adapter;

#define B11_GUEST_SLOT(vtbl_type, member) ((uint32_t)(offsetof(vtbl_type, member) / sizeof(void *) * 4u))

static HRESULT STDMETHODCALLTYPE b11_include_Open(ID3DInclude *This, D3D_INCLUDE_TYPE type, LPCSTR name, LPCVOID parent, LPCVOID *data,
                                              UINT *bytes) {
    b11_include_adapter *self = (b11_include_adapter *)This;
    uint32_t guest = self->guest, args[6], scratch;
    size_t len = strlen(name) + 1u;
    HRESULT hr;
    /* The parent is a buffer an earlier Open returned or the guest's source, guest memory either way; or it is
     * the file D3DX read for D3DX11CompileFromFileW, a buffer of the host's. The 32-bit program gets D3DX's
     * buffer too, an address it has never seen: here it gets one of its own that stands for it. */
    if ((uintptr_t)parent > 0xffffffffu) {
        if (self->host_parent == NULL && (self->parent_token = b11_host.galloc(1u, 1)) != 0u) {
            self->host_parent = parent;
        }
        if (self->host_parent != parent) {
            b11_host.stop("ID3DInclude::Open(\"%s\"): a second including file outside guest memory, or no guest memory", name);
            return E_FAIL;
        }
        parent = B11_GP(self->parent_token);
    }
    if (len > 0x10000u || (scratch = b11_host.galloc(8u + (uint32_t)len, 1)) == 0u) {
        b11_host.stop("ID3DInclude::Open(\"%s\"): the arguments cannot be passed to the guest", name);
        return E_FAIL;
    }
    memcpy(B11_GP(scratch + 8u), name, len); /* [0] ppData, [4] pBytes, [8] the file name */
    args[0] = guest;
    args[1] = (uint32_t)type;
    args[2] = scratch + 8u;
    args[3] = (uint32_t)(uintptr_t)parent;
    args[4] = scratch;
    args[5] = scratch + 4u;
    hr = (HRESULT)b11_host.call_guest(self->c, b11_rd32(b11_rd32(guest) + B11_GUEST_SLOT(struct ID3DIncludeVtbl, Open)), 6u, args);
    *data = B11_GP(b11_rd32(scratch));
    *bytes = b11_rd32(scratch + 4u);
    b11_host.gfree(scratch);
    return hr;
}

static HRESULT STDMETHODCALLTYPE b11_include_Close(ID3DInclude *This, LPCVOID data) {
    b11_include_adapter *self = (b11_include_adapter *)This;
    uint32_t guest = self->guest, args[2];
    args[0] = guest;
    args[1] = (uint32_t)(uintptr_t)data;
    return (HRESULT)b11_host.call_guest(self->c, b11_rd32(b11_rd32(guest) + B11_GUEST_SLOT(struct ID3DIncludeVtbl, Close)), 2u, args);
}

static struct ID3DIncludeVtbl b11_include_vtbl = {b11_include_Open, b11_include_Close};

/* The macro definitions and the include handler of a compile call, as the host compiler takes them. */
typedef struct b11_compile_in {
    D3D_SHADER_MACRO *defines;
    ID3DInclude *include;
    b11_include_adapter adapter;
} b11_compile_in;

static HRESULT b11_compile_begin(b11_compile_in *in, struct lift_ctx *c, uint32_t defines, uint32_t include, const char *what) {
    const g32_D3D_SHADER_MACRO *g = B11_GP(defines);
    uint32_t i, n = 0u;
    memset(in, 0, sizeof *in);
    if (include == (uint32_t)(uintptr_t)D3D_COMPILE_STANDARD_FILE_INCLUDE) {
        in->include = D3D_COMPILE_STANDARD_FILE_INCLUDE;
    } else if (include != 0u) {
        if (b11_host.call_guest == NULL) {
            b11_host.stop("%s: the guest's ID3DInclude at %08x needs d3d11_bridge_host_t.call_guest", what, include);
            return E_NOTIMPL;
        }
        in->adapter.base.lpVtbl = &b11_include_vtbl;
        in->adapter.c = c;
        in->adapter.guest = include;
        in->include = &in->adapter.base;
    }
    if (g != NULL) { /* the array ends at a null name */
        while (g[n].Name != 0u) {
            ++n;
        }
        in->defines = malloc(((size_t)n + 1u) * sizeof *in->defines);
        if (in->defines == NULL) {
            b11_host.stop("%s: no host memory for %u macro definitions", what, n);
            return E_OUTOFMEMORY;
        }
        for (i = 0u; i < n; ++i) {
            in->defines[i].Name = B11_GP(g[i].Name);
            in->defines[i].Definition = B11_GP(g[i].Definition);
        }
        in->defines[n].Name = NULL;
        in->defines[n].Definition = NULL;
    }
    return S_OK;
}

/* Either blob can come back whatever the result: warnings on success, no code on failure. */
static uint32_t b11_compile_end(b11_compile_in *in, HRESULT hr, ID3DBlob *code, uint32_t code_out, ID3DBlob *errors, uint32_t errors_out) {
    free(in->defines);
    if (in->adapter.parent_token != 0u) {
        b11_host.gfree(in->adapter.parent_token);
    }
    if (code_out != 0u) {
        b11_wr32(code_out, b11_wrap_out(code, K_ID3D10Blob));
    }
    if (errors_out != 0u) {
        b11_wr32(errors_out, b11_wrap_out(errors, K_ID3D10Blob));
    }
    return (uint32_t)hr;
}

/* HRESULT D3DCompile(LPCVOID pSrcData, SIZE_T SrcDataSize, LPCSTR pSourceName, const D3D_SHADER_MACRO *pDefines,
 *     ID3DInclude *pInclude, LPCSTR pEntrypoint, LPCSTR pTarget, UINT Flags1, UINT Flags2, ID3DBlob **ppCode,
 *     ID3DBlob **ppErrorMsgs)
 * The game calls it once, at 0x11462110, with an include handler of its own. */
static uint32_t b11_x_D3DCompile(struct lift_ctx *c, const uint32_t *a) {
    b11_compile_in in;
    ID3DBlob *code = NULL, *errors = NULL;
    HRESULT hr = b11_compile_begin(&in, c, a[3], a[4], "D3DCompile");
    if (FAILED(hr)) {
        return (uint32_t)hr;
    }
    hr = D3DCompile(B11_P(0), a[1], B11_P(2), in.defines, in.include, B11_P(5), B11_P(6), a[7], a[8], a[9] != 0u ? &code : NULL,
                    a[10] != 0u ? &errors : NULL);
    return b11_compile_end(&in, hr, code, a[9], errors, a[10]);
}

/* HRESULT D3DReflect(LPCVOID pSrcData, SIZE_T SrcDataSize, REFIID pInterface, void **ppReflector)
 * d3dcompiler_47 knows only its own reflection IID (it answers E_INVALIDARG to D3DCompiler_42's), so the
 * game's request is made with that one. The guest gets D3DCompiler_42's interface as far as the game uses
 * it; see B11_REFLECTION_SLOTS. */
static uint32_t b11_x_D3DReflect(struct lift_ctx *c, const uint32_t *a) {
    (void)c;
    const GUID *iid = B11_P(2);
    void *out = NULL;
    char text[40];
    HRESULT hr;
    if (iid == NULL || a[3] == 0u) {
        return (uint32_t)E_INVALIDARG;
    }
    b11_wr32(a[3], 0u);
    if (!IsEqualGUID(iid, &b11_IID_ID3D11ShaderReflection_42)) {
        hr = D3DReflect(B11_P(0), a[1], iid, &out);
        if (SUCCEEDED(hr) && out != NULL) {
            IUnknown_Release((IUnknown *)out);
            b11_guid_text(iid, text);
            b11_host.stop("D3DReflect for interface %s succeeded on the host: this interface has no bridge", text);
            hr = E_NOINTERFACE;
        }
        return (uint32_t)hr;
    }
    hr = D3DReflect(B11_P(0), a[1], &IID_ID3D11ShaderReflection, &out);
    return b11_out_obj(hr, out, K_Reflection, a[3]);
}

/* HRESULT D3DDisassemble(LPCVOID pSrcData, SIZE_T SrcDataSize, UINT Flags, LPCSTR szComments, ID3DBlob **ppDisassembly) */
static uint32_t b11_x_D3DDisassemble(struct lift_ctx *c, const uint32_t *a) {
    (void)c;
    ID3DBlob *out = NULL;
    const HRESULT hr = D3DDisassemble(B11_P(0), a[1], a[2], B11_P(3), a[4] != 0u ? &out : NULL);
    return b11_out_obj(hr, out, K_ID3D10Blob, a[4]);
}

/* ---- D3DX11: the four functions the game imports from d3dx11_42.dll, done by the host's 64-bit d3dx11_42.dll ----
 * The Windows SDK has no header for D3DX, so the argument lists are the game's own, at its four call sites
 * (image addresses; every call leaves its arguments to the callee):
 *
 *   0x11470c31  D3DX11FilterTexture(context, texture, 0, 3)
 *   0x1146338f, 0x11470cee
 *               D3DX11LoadTextureFromTexture(context, source, &info, destination). At 0x11470cee info is 40
 *               bytes of stack: two null pointers, then the dwords i - 1, i, 1, 0, 0, 0xffffffff, 5, 5, in a
 *               loop over i with source and destination the same texture: each mip level from the one above.
 *   0x11463ff8  D3DX11SaveTextureToFileA(context, texture, format, file name)
 *   0x11462000  D3DX11CompileFromFileW(file name, defines, an include handler of the game's (vtable 0x118c113c),
 *               entry point, profile, flags, 0, 0, &code, &errors, 0)
 *
 * They agree with the documented D3DX11 prototypes, whose names the structure below uses:
 * D3DX11_TEXTURE_LOAD_INFO is {D3D11_BOX *pSrcBox, *pDstBox; UINT SrcFirstMip, DstFirstMip, NumMips,
 * SrcFirstElement, DstFirstElement, NumElements, Filter, MipFilter}. The 64-bit DLL takes the same, with
 * 8-byte pointers. It is part of the DirectX End-User Runtime (June 2010); without it these calls stop the run. */
#define B11_D3DX_EXPORTS(E) \
    E("d3dx11_42.dll", D3DX11FilterTexture, 4, "iivv") \
    E("d3dx11_42.dll", D3DX11LoadTextureFromTexture, 4, "iipi") \
    E("d3dx11_42.dll", D3DX11SaveTextureToFileA, 4, "iivs") \
    E("d3dx11_42.dll", D3DX11CompileFromFileW, 11, "ppissvvpoop")

typedef struct g32_D3DX11_TEXTURE_LOAD_INFO {
    uint32_t pSrcBox, pDstBox;
    UINT SrcFirstMip, DstFirstMip, NumMips, SrcFirstElement, DstFirstElement, NumElements, Filter, MipFilter;
} g32_D3DX11_TEXTURE_LOAD_INFO;
_Static_assert(sizeof(g32_D3DX11_TEXTURE_LOAD_INFO) == 40, "the 40 bytes the game fills at 0x11470c88..0x11470ce4");
typedef struct b11_D3DX11_TEXTURE_LOAD_INFO {
    D3D11_BOX *pSrcBox, *pDstBox;
    UINT SrcFirstMip, DstFirstMip, NumMips, SrcFirstElement, DstFirstElement, NumElements, Filter, MipFilter;
} b11_D3DX11_TEXTURE_LOAD_INFO;

typedef HRESULT(WINAPI *b11_d3dx_filter)(ID3D11DeviceContext *, ID3D11Resource *, UINT, UINT);
typedef HRESULT(WINAPI *b11_d3dx_load)(ID3D11DeviceContext *, ID3D11Resource *, b11_D3DX11_TEXTURE_LOAD_INFO *, ID3D11Resource *);
typedef HRESULT(WINAPI *b11_d3dx_save)(ID3D11DeviceContext *, ID3D11Resource *, UINT, LPCSTR);
typedef HRESULT(WINAPI *b11_d3dx_compile)(LPCWSTR, const D3D_SHADER_MACRO *, ID3DInclude *, LPCSTR, LPCSTR, UINT, UINT, void *, ID3DBlob **,
                                           ID3DBlob **, HRESULT *);

/* A function of the host's d3dx11_42.dll, 0 (and the run stopped) when the DLL is not installed. */
static uintptr_t b11_d3dx(const char *name) {
    static volatile HMODULE lib;
    HMODULE dll = lib;
    FARPROC fn;
    if (dll == NULL) {
        lib = dll = LoadLibraryExW(L"d3dx11_42.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32); /* twice at worst: one module */
    }
    fn = dll != NULL ? GetProcAddress(dll, name) : NULL;
    if (fn == NULL) {
        b11_host.stop("%s: the host has no 64-bit d3dx11_42.dll (DirectX End-User Runtime, June 2010)", name);
    }
    return (uintptr_t)fn;
}

/* The device context and the one or two textures every one of them starts with. */
static int b11_d3dx_objects(const uint32_t *a, ID3D11DeviceContext **context, ID3D11Resource **first, uint32_t second_arg,
                            ID3D11Resource **second) {
    int bad = 0;
    *context = b11_arg(a[0], K_ID3D11DeviceContext, &bad);
    *first = b11_arg(a[1], K_ID3D11Resource, &bad);
    if (second != NULL) {
        *second = b11_arg(second_arg, K_ID3D11Resource, &bad);
    }
    return !bad;
}

static uint32_t b11_x_D3DX11FilterTexture(struct lift_ctx *c, const uint32_t *a) {
    const b11_d3dx_filter fn = (b11_d3dx_filter)b11_d3dx("D3DX11FilterTexture");
    ID3D11DeviceContext *context;
    ID3D11Resource *texture;
    (void)c;
    if (fn == NULL || !b11_d3dx_objects(a, &context, &texture, 0u, NULL)) {
        return (uint32_t)E_FAIL;
    }
    return (uint32_t)fn(context, texture, a[2], a[3]);
}

static uint32_t b11_x_D3DX11LoadTextureFromTexture(struct lift_ctx *c, const uint32_t *a) {
    const b11_d3dx_load fn = (b11_d3dx_load)b11_d3dx("D3DX11LoadTextureFromTexture");
    const g32_D3DX11_TEXTURE_LOAD_INFO *g = B11_P(2);
    b11_D3DX11_TEXTURE_LOAD_INFO info;
    ID3D11DeviceContext *context;
    ID3D11Resource *source, *destination;
    (void)c;
    if (fn == NULL || !b11_d3dx_objects(a, &context, &source, a[3], &destination)) {
        return (uint32_t)E_FAIL;
    }
    if (g != NULL) {
        info.pSrcBox = B11_GP(g->pSrcBox); /* D3D11_BOX is six dwords in both worlds */
        info.pDstBox = B11_GP(g->pDstBox);
        memcpy(&info.SrcFirstMip, &g->SrcFirstMip, 8u * sizeof(UINT));
    }
    return (uint32_t)fn(context, source, g != NULL ? &info : NULL, destination);
}

/* The one function here that writes a file of the host's: the runner decides whether it may. */
static uint32_t b11_x_D3DX11SaveTextureToFileA(struct lift_ctx *c, const uint32_t *a) {
    const b11_d3dx_save fn = (b11_d3dx_save)b11_d3dx("D3DX11SaveTextureToFileA");
    ID3D11DeviceContext *context;
    ID3D11Resource *texture;
    (void)c;
    if (fn == NULL || a[3] == 0u || !b11_d3dx_objects(a, &context, &texture, 0u, NULL)) {
        return (uint32_t)E_FAIL;
    }
    if (b11_host.may_write == NULL) {
        b11_host.stop("D3DX11SaveTextureToFileA(\"%s\") writes a file: it needs d3d11_bridge_host_t.may_write", (const char *)B11_P(3));
        return (uint32_t)E_NOTIMPL;
    }
    if (!b11_host.may_write(B11_P(3))) {
        return (uint32_t)E_ACCESSDENIED;
    }
    return (uint32_t)fn(context, texture, a[2], B11_P(3));
}

static uint32_t b11_x_D3DX11CompileFromFileW(struct lift_ctx *c, const uint32_t *a) {
    const b11_d3dx_compile fn = (b11_d3dx_compile)b11_d3dx("D3DX11CompileFromFileW");
    b11_compile_in in;
    ID3DBlob *code = NULL, *errors = NULL;
    HRESULT hr;
    if (fn == NULL) {
        return (uint32_t)E_FAIL;
    }
    if (a[7] != 0u) {
        b11_host.stop("D3DX11CompileFromFileW: a thread pump (%08x) is not bridged", a[7]);
        return (uint32_t)E_NOTIMPL;
    }
    hr = b11_compile_begin(&in, c, a[1], a[2], "D3DX11CompileFromFileW");
    if (FAILED(hr)) {
        return (uint32_t)hr;
    }
    hr = fn(B11_P(0), in.defines, in.include, B11_P(3), B11_P(4), a[5], a[6], NULL, a[8] != 0u ? &code : NULL, a[9] != 0u ? &errors : NULL,
            B11_P(10));
    return b11_compile_end(&in, hr, code, a[8], errors, a[9]);
}

#define B11_ALL_EXPORTS(E) B11_EXPORTS(E) B11_D3DX_EXPORTS(E)

/* What the guest calls: a bridge function, then the development aids when one is on. */
#define B11_WRAPPER(linkage, wrapper, ensure, inner, label, sig, ret) \
    linkage uint32_t wrapper(struct lift_ctx *c, const uint32_t *a) { \
        uint32_t r; \
        ensure; \
        r = inner(c, a); \
        if (b11_dev != 0u) { \
            b11_after(label, sig, ret, a, r); \
        } \
        return r; \
    }
#define B11_AS_WRAPPER(I, N, slot, nargs, ret, sig) B11_WRAPPER(static, b11_w_##I##_##N, (void)0, m_##I##_##N, #I "::" #N, sig, ret)
#define B11_AS_REFLECTION_WRAPPER(n, nargs, ret, sig) \
    B11_WRAPPER(static, b11_w_Reflection_slot##n, (void)0, m_Reflection_slot##n, "ID3D11ShaderReflection_42::slot" #n, sig, ret)
#define B11_AS_REFLECTION_CB_WRAPPER(n, nargs, ret, sig) \
    B11_WRAPPER(static, b11_w_ReflectionCB_slot##n, (void)0, m_ReflectionCB_slot##n, "ID3D11ShaderReflectionConstantBuffer_42::slot" #n, sig, ret)
#define B11_AS_ENTRY(dll, name, nargs, sig) B11_WRAPPER(, d3d11_bridge_##name, B11_ENSURE(), b11_x_##name, #name, sig, 'D')
B11_DECLARED(B11_AS_WRAPPER)
B11_REFLECTION_SLOTS(B11_AS_REFLECTION_WRAPPER)
B11_REFLECTION_CB_SLOTS(B11_AS_REFLECTION_CB_WRAPPER)
B11_ALL_EXPORTS(B11_AS_ENTRY)
const d3d11_bridge_export_t d3d11_bridge_exports[] = {B11_ALL_EXPORTS(B11_AS_EXPORT)};
const uint32_t d3d11_bridge_export_count = sizeof d3d11_bridge_exports / sizeof d3d11_bridge_exports[0];

/* ---- 7. inside live_main.c ---------------------------------------------------------------------
 * live.exe is built from live_main.c alone, so the bridge joins it as an included file. Two additions
 * to live_main.c, and none to the build:
 *
 *     #define D3D11_BRIDGE_LIVE
 *     #include "d3d11_bridge.c"         above g_shims; uses stop, galloc, gfree, import_addr, guest_call,
 *                                       write_allowed
 *
 *     static const shim g_shims[] = {
 *         ...
 *         D3D11_BRIDGE_SHIMS            no comma after it
 *     };
 *
 * The rows give the eleven entry points and every vtable slot a shim of the runner's own type, found by
 * the names the runner already uses: GetProcAddress and the import table by export name, a vtable slot as
 * "<interface>#<slot>" of the pseudo-DLL "com". The first call into the bridge initialises it. */
#ifdef D3D11_BRIDGE_LIVE

static int guest_call(uint32_t entry, uint32_t nargs, const uint32_t *args);

/* The address of a vtable slot is the address of its import record; the function and the argument count
 * come from the row of D3D11_BRIDGE_SHIMS with the same name. */
static uint32_t b11_live_register(const char *iface, uint32_t idx, uint32_t nargs, d3d11_bridge_fn fn) {
    char name[96];
    uint32_t va;
    (void)nargs;
    (void)fn;
    snprintf(name, sizeof name, "%s#%u", iface, idx);
#ifdef SH_FREE /* the runner with guest threads: g_lock guards its import table, and a free shim does not hold it */
    EnterCriticalSection(&g_lock);
#endif
    va = import_addr("com", name, 0u);
#ifdef SH_FREE
    LeaveCriticalSection(&g_lock);
#endif
    return va;
}

/* guest_call returns 1 when the run stopped, and leaves the callee's EAX in the calling thread's state. */
static uint32_t b11_live_call_guest(struct lift_ctx *c, uint32_t entry, uint32_t nargs, const uint32_t *args) {
    return guest_call(entry, nargs, args) ? (uint32_t)E_FAIL : c->r[LM_EAX];
}

/* fld dword ptr [rcx]; ret. While a shim runs the thread's x87 registers are the guest's (live_fp_enter makes
 * them so, and compiled x64 code does not use them): what is pushed here is the guest's st(0). */
#pragma section(".b11x", read, execute)
static __declspec(allocate(".b11x")) const unsigned char b11_live_fld[] = {0xd9, 0x01, 0xc3};
static void b11_live_return_float(struct lift_ctx *c, float v) {
    (void)c;
    ((void (*)(const float *))(uintptr_t)b11_live_fld)(&v);
}

/* The runner's rule for files the guest writes; it stops the run itself when the answer is no. */
static int b11_live_may_write(const char *path) { return write_allowed("D3DX11SaveTextureToFileA", path, NULL); }

static BOOL CALLBACK b11_live_once(PINIT_ONCE once, PVOID param, PVOID *context) {
    static const d3d11_bridge_host_t host = {galloc, gfree,           b11_live_register,     stop,
                                             b11_live_call_guest,     b11_live_return_float, b11_live_may_write};
    (void)once;
    (void)param;
    (void)context;
    d3d11_bridge_init(&host);
    return TRUE;
}

static void b11_live_init(void) {
    static INIT_ONCE once = INIT_ONCE_STATIC_INIT;
    InitOnceExecuteOnce(&once, b11_live_once, NULL, NULL);
}

/* A shim row. With guest threads the runner's rows are {dll, name, nargs, fn, flags}, and the bridge's
 * are free: it has its own lock, D3DCompile calls guest code, and Present and Map can block. Before
 * that they were {name, nargs, fn}. */
#ifdef SH_FREE
#define B11_ROW(dll, name, nargs, fn) {dll, name, nargs, fn, SH_FREE},
#else
#define B11_ROW(dll, name, nargs, fn) {name, nargs, fn},
#endif
#define B11_ROW_METHOD(I, N, slot, nargs, ret, sig) B11_ROW("com", #I "#" #slot, nargs, b11_w_##I##_##N)
#define B11_ROW_REFLECTION(n, nargs, ret, sig) B11_ROW("com", "ID3D11ShaderReflection_42#" #n, nargs, b11_w_Reflection_slot##n)
#define B11_ROW_REFLECTION_CB(n, nargs, ret, sig) \
    B11_ROW("com", "ID3D11ShaderReflectionConstantBuffer_42#" #n, nargs, b11_w_ReflectionCB_slot##n)
#define B11_ROW_EXPORT(dll, name, nargs, sig) B11_ROW(dll, #name, nargs, d3d11_bridge_##name)
#define D3D11_BRIDGE_SHIMS \
    B11_DECLARED(B11_ROW_METHOD) B11_REFLECTION_SLOTS(B11_ROW_REFLECTION) B11_REFLECTION_CB_SLOTS(B11_ROW_REFLECTION_CB) \
    B11_ALL_EXPORTS(B11_ROW_EXPORT)

#endif /* D3D11_BRIDGE_LIVE */
