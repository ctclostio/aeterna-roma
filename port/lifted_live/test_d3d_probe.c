/*
 * test_d3d_probe.c - a stand-in for a Direct3D 11 game, for `python scripts/lift/watch_game.py selftest`.
 *
 *     test_d3d_probe.exe [--start-ms N] [--open <file>]...
 *
 * The selftest builds this source as a 32-bit and as a 64-bit program of the same file name, watches each from
 * outside and requires the two records to be identical. The program does what a game does at start-up, in a fixed
 * order: it sleeps N ms (so that a monitor has seen the process), opens each named file for reading (a file that
 * does not exist is asked for like the others), creates a DXGI factory, walks the adapter and its first output,
 * creates a Direct3D 11 device on that adapter, a window that is never shown and a swap chain on it, asks DXGI about
 * the swap chain, creates a buffer and a texture of each kind (one buffer on a second thread), presents three
 * frames and resizes.
 *
 * It makes each call whose event the 32-bit and the 64-bit dxgi.dll were seen to report differently (see
 * scripts/lift/watch_d3d.py): IDXGIFactory::MakeWindowAssociation, IDXGIFactory::CreateSwapChain,
 * IDXGISwapChain::GetFullscreenState with no output asked for, and IDXGIFactory::CreateSoftwareAdapter (on the WARP
 * rasterizer's DLL, with an adapter pointer that is not null before the call); and IDXGISwapChain::GetDesc, whose
 * event holds a swap chain description as well.
 *
 * Every step prints its result. Exit code 1 when a step the rest depends on fails.
 */
#define COBJMACROS
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#pragma warning(push)
#pragma warning(disable : 4201)
#include <d3d11.h>
#include <dxgi.h>
#pragma warning(pop)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void step(const char *what, HRESULT hr)
{
    printf("%-44s %08lx\n", what, (unsigned long)hr);
    fflush(stdout);
}

static DWORD WINAPI worker(LPVOID device)
{
    D3D11_BUFFER_DESC desc;
    ID3D11Buffer *buffer = NULL;
    memset(&desc, 0, sizeof desc);
    desc.ByteWidth = 64;
    desc.Usage = D3D11_USAGE_DEFAULT;
    desc.BindFlags = D3D11_BIND_INDEX_BUFFER;
    step("ID3D11Device::CreateBuffer (second thread)", ID3D11Device_CreateBuffer((ID3D11Device *)device, &desc, NULL, &buffer));
    if (buffer) ID3D11Buffer_Release(buffer);
    return 0;
}

int main(int argc, char **argv)
{
    IDXGIFactory *factory = NULL;
    IDXGIFactory1 *factory1 = NULL;
    IDXGIAdapter *adapter = NULL, *soft = NULL;
    IDXGIAdapter1 *adapter1 = NULL;
    IDXGIOutput *output = NULL, *containing = NULL;
    IDXGISwapChain *chain = NULL;
    ID3D11Device *device = NULL;
    ID3D11DeviceContext *context = NULL;
    ID3D11Texture2D *back = NULL, *texture2 = NULL;
    ID3D11Texture1D *texture1 = NULL;
    ID3D11Texture3D *texture3 = NULL;
    ID3D11Buffer *buffer = NULL;
    ID3D11RenderTargetView *view = NULL;
    D3D_FEATURE_LEVEL wanted[1] = {D3D_FEATURE_LEVEL_11_0}, got = 0;
    DXGI_ADAPTER_DESC adapter_desc;
    DXGI_OUTPUT_DESC output_desc;
    DXGI_SWAP_CHAIN_DESC desc, chain_desc;
    DXGI_MODE_DESC mode, closest;
    D3D11_BUFFER_DESC buffer_desc;
    D3D11_TEXTURE1D_DESC t1;
    D3D11_TEXTURE2D_DESC t2;
    D3D11_TEXTURE3D_DESC t3;
    D3D11_SUBRESOURCE_DATA initial;
    LARGE_INTEGER version;
    WNDCLASSA wc;
    HWND window, associated = NULL;
    HANDLE thread;
    UINT modes = 0;
    BOOL fullscreen = FALSE;
    static float vertices[12];
    HRESULT hr;
    int i;

    printf("pid %lu, %u-bit\n", (unsigned long)GetCurrentProcessId(), (unsigned)(8 * sizeof(void *)));
    fflush(stdout);
    for (i = 1; i + 1 < argc; i += 2) {
        if (!strcmp(argv[i], "--start-ms")) {
            Sleep((DWORD)atoi(argv[i + 1]));
        } else if (!strcmp(argv[i], "--open")) {
            HANDLE h = CreateFileA(argv[i + 1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            printf("open %-39s %s\n", argv[i + 1], h == INVALID_HANDLE_VALUE ? "failed" : "ok");
            fflush(stdout);
            if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
        } else {
            break;
        }
    }
    if (i < argc) { fprintf(stderr, "unknown or incomplete argument %s\n", argv[i]); return 2; }

    /* The first DXGI call. */
    hr = CreateDXGIFactory(&IID_IDXGIFactory, (void **)&factory);
    step("CreateDXGIFactory", hr);
    if (FAILED(hr)) return 1;
    hr = IDXGIFactory_EnumAdapters(factory, 0, &adapter);
    step("IDXGIFactory::EnumAdapters(0)", hr);
    if (FAILED(hr)) return 1;
    step("IDXGIAdapter::GetDesc", IDXGIAdapter_GetDesc(adapter, &adapter_desc));
    step("IDXGIAdapter::CheckInterfaceSupport", IDXGIAdapter_CheckInterfaceSupport(adapter, &IID_ID3D10Device, &version));
    hr = IDXGIAdapter_EnumOutputs(adapter, 0, &output);
    step("IDXGIAdapter::EnumOutputs(0)", hr);
    if (SUCCEEDED(hr)) {
        step("IDXGIOutput::GetDesc", IDXGIOutput_GetDesc(output, &output_desc));
        step("IDXGIOutput::GetDisplayModeList(count)", IDXGIOutput_GetDisplayModeList(output, DXGI_FORMAT_R8G8B8A8_UNORM, 0, &modes, NULL));
        memset(&mode, 0, sizeof mode);
        mode.Width = 800; mode.Height = 600; mode.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
        step("IDXGIOutput::FindClosestMatchingMode", IDXGIOutput_FindClosestMatchingMode(output, &mode, &closest, NULL));
    }
    /* The DXGI 1.1 way, which the events do not report method by method. */
    hr = CreateDXGIFactory1(&IID_IDXGIFactory1, (void **)&factory1);
    step("CreateDXGIFactory1", hr);
    if (SUCCEEDED(hr)) {
        hr = IDXGIFactory1_EnumAdapters1(factory1, 0, &adapter1);
        step("IDXGIFactory1::EnumAdapters1(0)", hr);
        if (SUCCEEDED(hr)) IDXGIAdapter1_Release(adapter1);
        IDXGIFactory1_Release(factory1);
    }

    hr = D3D11CreateDevice(adapter, D3D_DRIVER_TYPE_UNKNOWN, NULL, 0, wanted, 1, D3D11_SDK_VERSION, &device, &got, &context);
    step("D3D11CreateDevice", hr);
    if (FAILED(hr)) return 1;

    memset(&wc, 0, sizeof wc);
    wc.lpfnWndProc = DefWindowProcA;
    wc.hInstance = GetModuleHandleA(NULL);
    wc.lpszClassName = "aeterna_d3d_probe";
    RegisterClassA(&wc);
    window = CreateWindowExA(0, wc.lpszClassName, "probe", WS_OVERLAPPEDWINDOW, 0, 0, 320, 240, NULL, NULL, wc.hInstance, NULL);
    if (!window) { fprintf(stderr, "no window\n"); return 1; }

    /* Windowed, SwapEffect and Flags are all non-zero, so a description read in the wrong layout shows. */
    memset(&desc, 0, sizeof desc);
    desc.BufferDesc.Width = 320;
    desc.BufferDesc.Height = 240;
    desc.BufferDesc.RefreshRate.Numerator = 60;
    desc.BufferDesc.RefreshRate.Denominator = 1;
    desc.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    desc.SampleDesc.Count = 1;
    desc.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    desc.BufferCount = 2;
    desc.OutputWindow = window;
    desc.Windowed = TRUE;
    desc.SwapEffect = DXGI_SWAP_EFFECT_SEQUENTIAL;
    desc.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
    hr = IDXGIFactory_CreateSwapChain(factory, (IUnknown *)device, &desc, &chain);
    step("IDXGIFactory::CreateSwapChain", hr);
    if (FAILED(hr)) return 1;
    step("IDXGIFactory::MakeWindowAssociation", IDXGIFactory_MakeWindowAssociation(factory, window, DXGI_MWA_NO_ALT_ENTER | DXGI_MWA_NO_WINDOW_CHANGES));
    step("IDXGIFactory::GetWindowAssociation", IDXGIFactory_GetWindowAssociation(factory, &associated));
    step("IDXGISwapChain::GetDesc", IDXGISwapChain_GetDesc(chain, &chain_desc));
    step("IDXGISwapChain::GetFullscreenState", IDXGISwapChain_GetFullscreenState(chain, &fullscreen, NULL));
    step("IDXGISwapChain::SetFullscreenState(FALSE)", IDXGISwapChain_SetFullscreenState(chain, FALSE, NULL));
    hr = IDXGISwapChain_GetContainingOutput(chain, &containing);
    step("IDXGISwapChain::GetContainingOutput", hr);
    if (SUCCEEDED(hr)) IDXGIOutput_Release(containing);
    /* What `soft` holds before the call is what the event reports as ppAdapter: not null, so that the field shows. */
    soft = (IDXGIAdapter *)(size_t)0x12345678;
    hr = IDXGIFactory_CreateSoftwareAdapter(factory, LoadLibraryA("d3d10warp.dll"), &soft);
    step("IDXGIFactory::CreateSoftwareAdapter", hr);
    if (SUCCEEDED(hr)) IDXGIAdapter_Release(soft);

    hr = IDXGISwapChain_GetBuffer(chain, 0, &IID_ID3D11Texture2D, (void **)&back);
    step("IDXGISwapChain::GetBuffer", hr);
    if (FAILED(hr)) return 1;
    hr = ID3D11Device_CreateRenderTargetView(device, (ID3D11Resource *)back, NULL, &view);
    step("ID3D11Device::CreateRenderTargetView", hr);
    if (FAILED(hr)) return 1;
    ID3D11DeviceContext_OMSetRenderTargets(context, 1, &view, NULL);

    memset(&buffer_desc, 0, sizeof buffer_desc);
    buffer_desc.ByteWidth = sizeof vertices;
    buffer_desc.Usage = D3D11_USAGE_DEFAULT;
    buffer_desc.BindFlags = D3D11_BIND_VERTEX_BUFFER;
    memset(&initial, 0, sizeof initial);
    initial.pSysMem = vertices;
    step("ID3D11Device::CreateBuffer", ID3D11Device_CreateBuffer(device, &buffer_desc, &initial, &buffer));
    thread = CreateThread(NULL, 0, worker, device, 0, NULL);
    if (thread) { WaitForSingleObject(thread, INFINITE); CloseHandle(thread); }

    memset(&t1, 0, sizeof t1);
    t1.Width = 64; t1.MipLevels = 1; t1.ArraySize = 1; t1.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    t1.Usage = D3D11_USAGE_DEFAULT; t1.BindFlags = D3D11_BIND_SHADER_RESOURCE;
    step("ID3D11Device::CreateTexture1D", ID3D11Device_CreateTexture1D(device, &t1, NULL, &texture1));
    memset(&t2, 0, sizeof t2);
    t2.Width = 128; t2.Height = 64; t2.MipLevels = 1; t2.ArraySize = 1; t2.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    t2.SampleDesc.Count = 1; t2.Usage = D3D11_USAGE_DEFAULT; t2.BindFlags = D3D11_BIND_SHADER_RESOURCE | D3D11_BIND_RENDER_TARGET;
    step("ID3D11Device::CreateTexture2D", ID3D11Device_CreateTexture2D(device, &t2, NULL, &texture2));
    memset(&t3, 0, sizeof t3);
    t3.Width = 16; t3.Height = 16; t3.Depth = 4; t3.MipLevels = 1; t3.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    t3.Usage = D3D11_USAGE_DEFAULT; t3.BindFlags = D3D11_BIND_SHADER_RESOURCE;
    step("ID3D11Device::CreateTexture3D", ID3D11Device_CreateTexture3D(device, &t3, NULL, &texture3));

    for (i = 0; i < 3; i++) {
        float colour[4] = {0.1f * (float)i, 0.2f, 0.3f, 1.0f};
        ID3D11DeviceContext_ClearRenderTargetView(context, view, colour);
        step("IDXGISwapChain::Present", IDXGISwapChain_Present(chain, 0, 0));
    }

    /* A resize, as a game does when its window changes: the back buffer must be released first. */
    ID3D11DeviceContext_OMSetRenderTargets(context, 0, NULL, NULL);
    ID3D11RenderTargetView_Release(view);
    ID3D11Texture2D_Release(back);
    ID3D11DeviceContext_ClearState(context);
    ID3D11DeviceContext_Flush(context);
    step("IDXGISwapChain::ResizeBuffers", IDXGISwapChain_ResizeBuffers(chain, 2, 400, 300, DXGI_FORMAT_R8G8B8A8_UNORM, DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH));
    memset(&mode, 0, sizeof mode);
    mode.Width = 400; mode.Height = 300; mode.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    step("IDXGISwapChain::ResizeTarget", IDXGISwapChain_ResizeTarget(chain, &mode));
    step("IDXGISwapChain::Present", IDXGISwapChain_Present(chain, 0, 0));

    if (texture3) ID3D11Texture3D_Release(texture3);
    if (texture2) ID3D11Texture2D_Release(texture2);
    if (texture1) ID3D11Texture1D_Release(texture1);
    if (buffer) ID3D11Buffer_Release(buffer);
    IDXGISwapChain_Release(chain);
    ID3D11DeviceContext_Release(context);
    ID3D11Device_Release(device);
    if (output) IDXGIOutput_Release(output);
    IDXGIAdapter_Release(adapter);
    IDXGIFactory_Release(factory);
    DestroyWindow(window);
    printf("done\n");
    return 0;
}
