/* NetWatch desktop window. It talks to the local Python helper and never sends packets. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <strsafe.h>
#include <string.h>

#define IDC_CONFIRM 101
#define IDC_ACCEPT 102
#define IDC_PROTECT 103
#define IDC_FORGET 104
#define IDC_PING 105
#define IDC_MITM 106
#define IDC_REDIRECT 107
#define IDC_RESET 108
#define WM_RESULT (WM_APP + 1)

typedef struct {
    wchar_t *report;
    wchar_t *message;
    int confirm;
    int accept;
    int protect;
    int forget;
    int reset;
} Result;

static HWND g_hwnd, g_edit, g_status;
static HWND g_confirm, g_accept, g_protect, g_forget, g_reset;
static HFONT g_font;
static HANDLE g_proc, g_in_w, g_out_r;
static volatile LONG g_busy;

static wchar_t *widen(const char *utf8) {
    int need;
    wchar_t *out;
    if (!utf8) utf8 = "";
    need = MultiByteToWideChar(CP_UTF8, 0, utf8, -1, NULL, 0);
    if (need <= 0) need = 1;
    out = (wchar_t *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (size_t)need * sizeof(wchar_t));
    if (!out) return NULL;
    MultiByteToWideChar(CP_UTF8, 0, utf8, -1, out, need);
    return out;
}

static void free_result(Result *result) {
    if (!result) return;
    if (result->report) HeapFree(GetProcessHeap(), 0, result->report);
    if (result->message) HeapFree(GetProcessHeap(), 0, result->message);
    HeapFree(GetProcessHeap(), 0, result);
}

static int line_value(const char *frame, const char *key) {
    const char *found = strstr(frame, key);
    if (!found) return 0;
    return found[strlen(key)] == '1';
}

static Result *parse_frame(const char *frame) {
    const char *report_at;
    const char *end;
    char *report_utf8;
    char message[512];
    const char *msg;
    const char *nl;
    size_t n;
    Result *result = (Result *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(Result));
    if (!result) return NULL;
    result->confirm = line_value(frame, "\nCONFIRM ");
    result->accept = line_value(frame, "\nACCEPT ");
    result->protect = line_value(frame, "\nPROTECT ");
    result->forget = line_value(frame, "\nFORGET ");
    result->reset = strstr(frame, "\nVIEW demo\n") != NULL;
    msg = strstr(frame, "\nMESSAGE ");
    message[0] = 0;
    if (msg) {
        msg += 9;
        nl = strchr(msg, '\n');
        n = nl ? (size_t)(nl - msg) : strlen(msg);
        if (n > sizeof(message) - 1) n = sizeof(message) - 1;
        memcpy(message, msg, n);
        message[n] = 0;
    }
    result->message = widen(message);
    report_at = strstr(frame, "\nREPORT\n");
    end = report_at ? strstr(report_at, "\nEND\n") : NULL;
    if (report_at && end && end > report_at + 8) {
        report_at += 8;
        n = (size_t)(end - report_at);
        report_utf8 = (char *)HeapAlloc(GetProcessHeap(), 0, n + 1);
        if (report_utf8) {
            memcpy(report_utf8, report_at, n);
            report_utf8[n] = 0;
            result->report = widen(report_utf8);
            HeapFree(GetProcessHeap(), 0, report_utf8);
        }
    }
    if (!result->report) result->report = widen("NetWatch did not receive a report.");
    return result;
}

static int read_frame(char *buf, int cap) {
    int used = 0;
    DWORD start = GetTickCount();
    buf[0] = 0;
    while (used < cap - 1) {
        DWORD avail = 0;
        DWORD got = 0;
        if (!PeekNamedPipe(g_out_r, NULL, 0, NULL, &avail, NULL)) return 0;
        if (avail == 0) {
            if (GetTickCount() - start > 20000) return 0;
            Sleep(30);
            continue;
        }
        if (used + (int)avail >= cap - 1) avail = (DWORD)(cap - 1 - used);
        if (!ReadFile(g_out_r, buf + used, avail, &got, NULL) || got == 0) return 0;
        used += (int)got;
        buf[used] = 0;
        if (strstr(buf, "\nEND\n")) return 1;
        start = GetTickCount();
    }
    return 0;
}

static DWORD WINAPI command_thread(LPVOID param) {
    char *command = (char *)param;
    char *buf;
    DWORD wrote = 0;
    Result *result;
    if (!WriteFile(g_in_w, command, (DWORD)strlen(command), &wrote, NULL)) {
        HeapFree(GetProcessHeap(), 0, command);
        result = (Result *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(Result));
        if (result) result->report = widen("NetWatch could not talk to its helper.");
        PostMessageW(g_hwnd, WM_RESULT, 0, (LPARAM)result);
        return 0;
    }
    HeapFree(GetProcessHeap(), 0, command);
    buf = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 256 * 1024);
    if (!buf || !read_frame(buf, 256 * 1024)) {
        result = (Result *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(Result));
        if (result) result->report = widen("NetWatch timed out waiting for a reading.");
    } else {
        result = parse_frame(buf);
    }
    if (buf) HeapFree(GetProcessHeap(), 0, buf);
    PostMessageW(g_hwnd, WM_RESULT, 0, (LPARAM)result);
    return 0;
}

static void send_command(const char *text) {
    char *copy;
    HANDLE thread;
    if (InterlockedCompareExchange(&g_busy, 1, 0) != 0) return;
    copy = (char *)HeapAlloc(GetProcessHeap(), 0, strlen(text) + 1);
    if (!copy) {
        InterlockedExchange(&g_busy, 0);
        return;
    }
    memcpy(copy, text, strlen(text) + 1);
    thread = CreateThread(NULL, 0, command_thread, copy, 0, NULL);
    if (thread) CloseHandle(thread);
    else InterlockedExchange(&g_busy, 0);
}

static int start_helper(void) {
    wchar_t dir[MAX_PATH];
    wchar_t python[MAX_PATH];
    wchar_t command[MAX_PATH * 2];
    SECURITY_ATTRIBUTES sa;
    HANDLE in_r = NULL, out_w = NULL;
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    GetModuleFileNameW(NULL, dir, MAX_PATH);
    if (wcsrchr(dir, L'\\')) *wcsrchr(dir, L'\\') = 0;
    StringCchPrintfW(python, MAX_PATH, L"%s\\pythonw.exe", dir);
    StringCchPrintfW(command, MAX_PATH * 2, L"\"%s\" -u -m netwatch.bridge", python);
    ZeroMemory(&sa, sizeof(sa));
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    if (!CreatePipe(&in_r, &g_in_w, &sa, 0)) return 0;
    if (!CreatePipe(&g_out_r, &out_w, &sa, 0)) return 0;
    SetHandleInformation(g_in_w, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(g_out_r, HANDLE_FLAG_INHERIT, 0);
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdInput = in_r;
    si.hStdOutput = out_w;
    si.hStdError = out_w;
    ZeroMemory(&pi, sizeof(pi));
    if (!CreateProcessW(python, command, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, dir, &si, &pi)) {
        return 0;
    }
    g_proc = pi.hProcess;
    CloseHandle(pi.hThread);
    CloseHandle(in_r);
    CloseHandle(out_w);
    return 1;
}

static HWND add_button(HWND parent, int id, const wchar_t *label, int x, int y) {
    return CreateWindowExW(0, L"BUTTON", label, WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                           x, y, 150, 28, parent, (HMENU)(INT_PTR)id, GetModuleHandleW(NULL), NULL);
}

static void apply_result(Result *result) {
    if (!result) return;
    SetWindowTextW(g_edit, result->report ? result->report : L"");
    SetWindowTextW(g_status, result->message ? result->message : L"");
    EnableWindow(g_confirm, result->confirm);
    EnableWindow(g_accept, result->accept);
    EnableWindow(g_protect, result->protect);
    EnableWindow(g_forget, result->forget);
    EnableWindow(g_reset, result->reset);
    free_result(result);
    InterlockedExchange(&g_busy, 0);
}

static void layout(int width, int height) {
    MoveWindow(g_edit, 12, 112, width - 24, height - 124, TRUE);
}

static LRESULT CALLBACK wndproc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
    switch (msg) {
    case WM_CREATE:
        g_hwnd = hwnd;
        g_font = CreateFontW(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                             OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                             DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
        CreateWindowExW(0, L"STATIC",
                        L"NetWatch    desktop app for this PC    pings and LAN man-in-the-middle signs",
                        WS_CHILD | WS_VISIBLE, 12, 8, 860, 22, hwnd, NULL, NULL, NULL);
        g_confirm = add_button(hwnd, IDC_CONFIRM, L"Confirm router", 12, 36);
        g_accept = add_button(hwnd, IDC_ACCEPT, L"Accept new MAC", 170, 36);
        g_protect = add_button(hwnd, IDC_PROTECT, L"Pin the MAC", 328, 36);
        g_forget = add_button(hwnd, IDC_FORGET, L"Forget it", 486, 36);
        add_button(hwnd, IDC_PING, L"Simulate ping", 12, 70);
        add_button(hwnd, IDC_MITM, L"Simulate MITM", 170, 70);
        add_button(hwnd, IDC_REDIRECT, L"Simulate redirect", 328, 70);
        g_reset = add_button(hwnd, IDC_RESET, L"End simulation", 486, 70);
        g_status = CreateWindowExW(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE,
                                   650, 74, 300, 22, hwnd, NULL, NULL, NULL);
        g_edit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                 WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | WS_VSCROLL,
                                 12, 112, 940, 520, hwnd, NULL, NULL, NULL);
        SendMessageW(g_edit, WM_SETFONT, (WPARAM)g_font, TRUE);
        SendMessageW(g_status, WM_SETFONT, (WPARAM)g_font, TRUE);
        if (!start_helper()) {
            SetWindowTextW(g_edit,
                           L"NetWatch could not start. Keep NetWatch.exe in the same folder as pythonw.exe.");
            return 0;
        }
        SetTimer(hwnd, 1, 2000, NULL);
        send_command("state\n");
        return 0;
    case WM_SIZE:
        layout(LOWORD(lparam), HIWORD(lparam));
        return 0;
    case WM_TIMER:
        send_command("state\n");
        return 0;
    case WM_COMMAND:
        switch (LOWORD(wparam)) {
        case IDC_CONFIRM: send_command("confirm\n"); break;
        case IDC_ACCEPT: send_command("accept\n"); break;
        case IDC_PROTECT: send_command("protect\n"); break;
        case IDC_FORGET: send_command("forget\n"); break;
        case IDC_PING: send_command("ping\n"); break;
        case IDC_MITM: send_command("mitm\n"); break;
        case IDC_REDIRECT: send_command("redirect\n"); break;
        case IDC_RESET: send_command("reset\n"); break;
        }
        return 0;
    case WM_RESULT:
        apply_result((Result *)lparam);
        return 0;
    case WM_DESTROY:
        KillTimer(hwnd, 1);
        if (g_in_w) {
            DWORD wrote = 0;
            WriteFile(g_in_w, "quit\n", 5, &wrote, NULL);
            CloseHandle(g_in_w);
            g_in_w = NULL;
        }
        if (g_proc) {
            WaitForSingleObject(g_proc, 1000);
            TerminateProcess(g_proc, 0);
            CloseHandle(g_proc);
        }
        if (g_out_r) CloseHandle(g_out_r);
        if (g_font) DeleteObject(g_font);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wparam, lparam);
}

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE prev, PWSTR cmdline, int show) {
    WNDCLASSW wc;
    HWND hwnd;
    MSG msg;
    (void)prev;
    (void)cmdline;
    SetProcessDPIAware();
    ZeroMemory(&wc, sizeof(wc));
    wc.lpfnWndProc = wndproc;
    wc.hInstance = instance;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"NetWatchWindow";
    RegisterClassW(&wc);
    hwnd = CreateWindowExW(0, L"NetWatchWindow", L"NetWatch",
                           WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                           CW_USEDEFAULT, CW_USEDEFAULT, 980, 720,
                           NULL, NULL, instance, NULL);
    if (!hwnd) return 1;
    ShowWindow(hwnd, show);
    while (GetMessageW(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return (int)msg.wParam;
}
