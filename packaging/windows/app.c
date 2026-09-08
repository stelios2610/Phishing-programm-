#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <commctrl.h>
#include <shellapi.h>
#include <strsafe.h>
#include <wchar.h>
#include <string.h>

#pragma comment(lib, "comctl32.lib")

#define IDC_URL 101
#define IDC_ANALYZE 102
#define IDC_LANG 103
#define IDC_VERDICT 104
#define IDC_META 105
#define IDC_OUT 106
#define IDC_LOGO 107
#define IDC_TITLE 108
#define IDC_EX0 200

#define MAX_URL 8000
#define MAX_OUT 32000

static HWND g_url, g_verdict, g_meta, g_out, g_analyze, g_lang, g_logo, g_title;
static HFONT g_font, g_fontBig;
static HBRUSH g_bg, g_edit;
static HBITMAP g_bmp = NULL;
static int g_el = 1;
static wchar_t g_exedir[MAX_PATH];

static const wchar_t *EX_LABELS[] = {
    L"Microsoft official",
    L"Subdomain trap",
    L"Typosquat",
    L"@ trick",
    L"gov.gr kit",
    L"PayPal IP",
};
static const wchar_t *EX_URLS[] = {
    L"https://login.microsoftonline.com/",
    L"https://login.microsoft.com.secure-auth.xyz/signin",
    L"https://micros0ft-online.com/login",
    L"https://login.microsoftonline.com@evil.example/login",
    L"https://gov-gr-taxisnet.web.app/login",
    L"http://185.22.10.4/paypal/webscr?cmd=_login",
};

static void set_exe_dir(void) {
    GetModuleFileNameW(NULL, g_exedir, MAX_PATH);
    wchar_t *slash = wcsrchr(g_exedir, L'\\');
    if (slash) *slash = 0;
}

static int utf8_to_wide(const char *src, wchar_t *dst, int dstcch) {
    if (!src || !src[0]) { dst[0] = 0; return 0; }
    return MultiByteToWideChar(CP_UTF8, 0, src, -1, dst, dstcch);
}

static int wide_to_utf8(const wchar_t *src, char *dst, int dstcb) {
    return WideCharToMultiByte(CP_UTF8, 0, src, -1, dst, dstcb, NULL, NULL);
}

static void unescape(wchar_t *s) {
    wchar_t *r = s, *w = s;
    while (*r) {
        if (*r == L'\\' && r[1] == L'n') { *w++ = L'\n'; r += 2; }
        else if (*r == L'\\' && r[1] == L'\\') { *w++ = L'\\'; r += 2; }
        else *w++ = *r++;
    }
    *w = 0;
}

typedef struct {
    wchar_t verdict[64];
    wchar_t verdict_el[64];
    wchar_t score[16];
    wchar_t normalized[2048];
    wchar_t host[512];
    wchar_t official[128];
    wchar_t impersonated[128];
    wchar_t findings[MAX_OUT];
} Report;

static void parse_report(const char *utf8, Report *rep) {
    ZeroMemory(rep, sizeof(*rep));
    wchar_t line[4096];
    const char *p = utf8;
    while (*p) {
        const char *nl = strchr(p, '\n');
        size_t n = nl ? (size_t)(nl - p) : strlen(p);
        char tmp[4096];
        if (n >= sizeof(tmp)) n = sizeof(tmp) - 1;
        memcpy(tmp, p, n);
        tmp[n] = 0;
        if (n && tmp[n - 1] == '\r') tmp[n - 1] = 0;
        utf8_to_wide(tmp, line, 4096);
        if (wcsncmp(line, L"verdict=", 8) == 0) StringCchCopyW(rep->verdict, 64, line + 8);
        else if (wcsncmp(line, L"verdict_el=", 11) == 0) StringCchCopyW(rep->verdict_el, 64, line + 11);
        else if (wcsncmp(line, L"score=", 6) == 0) StringCchCopyW(rep->score, 16, line + 6);
        else if (wcsncmp(line, L"normalized=", 11) == 0) StringCchCopyW(rep->normalized, 2048, line + 11);
        else if (wcsncmp(line, L"host=", 5) == 0) StringCchCopyW(rep->host, 512, line + 5);
        else if (wcsncmp(line, L"official=", 9) == 0) StringCchCopyW(rep->official, 128, line + 9);
        else if (wcsncmp(line, L"impersonated=", 13) == 0) StringCchCopyW(rep->impersonated, 128, line + 13);
        else if (wcsncmp(line, L"finding\t", 8) == 0) {
            wchar_t *s1, *s2, *s3, *s4, *s5;
            s1 = line + 8;
            s2 = wcschr(s1, L'\t'); if (!s2) goto next; *s2++ = 0;
            s3 = wcschr(s2, L'\t'); if (!s3) goto next; *s3++ = 0;
            s4 = wcschr(s3, L'\t'); if (!s4) goto next; *s4++ = 0;
            s5 = wcschr(s4, L'\t'); if (!s5) goto next; *s5++ = 0;
            unescape(s2); unescape(s3); unescape(s4); unescape(s5);
            wchar_t block[2048];
            const wchar_t *title = g_el ? s3 : s2;
            const wchar_t *detail = g_el ? s5 : s4;
            StringCchPrintfW(block, 2048, L"[%s] %s\r\n    %s\r\n\r\n", s1, title, detail);
            StringCchCatW(rep->findings, MAX_OUT, block);
        }
    next:
        p = nl ? nl + 1 : p + strlen(p);
    }
    unescape(rep->normalized);
}

static BOOL run_analyze(const wchar_t *url, char *out_utf8, DWORD out_cb) {
    wchar_t python[MAX_PATH], script[MAX_PATH], cmd[1024];
    StringCchPrintfW(python, MAX_PATH, L"%s\\runtime\\python.exe", g_exedir);
    StringCchPrintfW(script, MAX_PATH, L"%s\\runtime\\analyze_bridge.py", g_exedir);
    StringCchPrintfW(cmd, 1024, L"\"%s\" -X utf8 \"%s\"", python, script);

    SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, TRUE};
    HANDLE in_r, in_w, out_r, out_w;
    if (!CreatePipe(&in_r, &in_w, &sa, 0)) return FALSE;
    if (!CreatePipe(&out_r, &out_w, &sa, 0)) { CloseHandle(in_r); CloseHandle(in_w); return FALSE; }
    SetHandleInformation(in_w, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(out_r, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdInput = in_r;
    si.hStdOutput = out_w;
    si.hStdError = out_w;

    BOOL ok = CreateProcessW(NULL, cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, g_exedir, &si, &pi);
    CloseHandle(in_r);
    CloseHandle(out_w);
    if (!ok) {
        CloseHandle(in_w);
        CloseHandle(out_r);
        return FALSE;
    }

    char url8[MAX_URL * 3];
    wide_to_utf8(url, url8, sizeof(url8));
    DWORD wr;
    WriteFile(in_w, url8, (DWORD)strlen(url8), &wr, NULL);
    CloseHandle(in_w);

    DWORD total = 0, rd;
    while (total + 1 < out_cb && ReadFile(out_r, out_utf8 + total, out_cb - total - 1, &rd, NULL) && rd)
        total += rd;
    out_utf8[total] = 0;
    CloseHandle(out_r);
    WaitForSingleObject(pi.hProcess, 25000);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return total > 0;
}

static COLORREF verdict_color(const wchar_t *v) {
    if (!wcscmp(v, L"official") || !wcscmp(v, L"likely_safe")) return RGB(61, 214, 140);
    if (!wcscmp(v, L"suspicious")) return RGB(245, 197, 66);
    return RGB(255, 93, 108);
}

static void do_analyze(HWND hwnd) {
    wchar_t url[MAX_URL];
    GetWindowTextW(g_url, url, MAX_URL);
    if (!url[0]) return;
    char raw[65536];
    if (!run_analyze(url, raw, sizeof(raw))) {
        SetWindowTextW(g_verdict, g_el ? L"Αποτυχία ανάλυσης" : L"Analysis failed");
        SetWindowTextW(g_out, L"Could not start the analysis engine (python runtime).");
        return;
    }
    Report rep;
    parse_report(raw, &rep);
    wchar_t head[256];
    const wchar_t *lab = g_el ? rep.verdict_el : rep.verdict;
    StringCchPrintfW(head, 256, L"%s  ·  %s %s/100", lab, g_el ? L"Κίνδυνος" : L"Risk", rep.score);
    SetWindowTextW(g_verdict, head);

    wchar_t meta[4096];
    StringCchCopyW(meta, 4096, rep.normalized[0] ? rep.normalized : url);
    if (rep.official[0]) {
        StringCchCatW(meta, 4096, g_el ? L"  ·  Επίσημο: " : L"  ·  Official: ");
        StringCchCatW(meta, 4096, rep.official);
    }
    if (rep.impersonated[0]) {
        StringCchCatW(meta, 4096, g_el ? L"  ·  Μοιάζει με: " : L"  ·  Looks like: ");
        StringCchCatW(meta, 4096, rep.impersonated);
    }
    SetWindowTextW(g_meta, meta);
    SetWindowTextW(g_out, rep.findings[0] ? rep.findings : (g_el ? L"Κανένα εύρημα." : L"No findings."));
    (void)hwnd;
}

static void layout(HWND hwnd) {
    RECT rc; GetClientRect(hwnd, &rc);
    int w = rc.right, y = 16;
    MoveWindow(g_logo, 16, 10, 48, 48, TRUE);
    MoveWindow(g_title, 76, 18, 280, 32, TRUE);
    MoveWindow(g_lang, w - 90, 16, 70, 28, TRUE);
    MoveWindow(g_url, 20, 56, w - 170, 32, TRUE);
    MoveWindow(g_analyze, w - 140, 56, 120, 32, TRUE);
    int x = 20;
    for (int i = 0; i < 6; i++) {
        HWND b = GetDlgItem(hwnd, IDC_EX0 + i);
        MoveWindow(b, x, 98, 140, 26, TRUE);
        x += 148;
    }
    MoveWindow(g_verdict, 20, 136, w - 40, 28, TRUE);
    MoveWindow(g_meta, 20, 166, w - 40, 40, TRUE);
    MoveWindow(g_out, 20, 214, w - 40, rc.bottom - 230, TRUE);
    (void)y;
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        g_bg = CreateSolidBrush(RGB(7, 9, 15));
        g_edit = CreateSolidBrush(RGB(11, 15, 24));
        g_font = CreateFontW(-16, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, L"Segoe UI");
        g_fontBig = CreateFontW(-22, 0, 0, 0, FW_BOLD, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, L"Segoe UI");
        g_logo = CreateWindowW(L"STATIC", NULL, WS_CHILD | WS_VISIBLE | SS_BITMAP | SS_CENTERIMAGE,
                               16, 10, 48, 48, hwnd, (HMENU)(INT_PTR)IDC_LOGO, NULL, NULL);
        {
            wchar_t bmp[MAX_PATH];
            StringCchPrintfW(bmp, MAX_PATH, L"%s\\logo.bmp", g_exedir);
            g_bmp = (HBITMAP)LoadImageW(NULL, bmp, IMAGE_BITMAP, 48, 48, LR_LOADFROMFILE | LR_CREATEDIBSECTION);
            if (g_bmp)
                SendMessageW(g_logo, STM_SETIMAGE, IMAGE_BITMAP, (LPARAM)g_bmp);
        }
        g_title = CreateWindowW(L"STATIC", L"PhishGuard", WS_CHILD | WS_VISIBLE, 76, 18, 300, 32, hwnd, (HMENU)(INT_PTR)IDC_TITLE, NULL, NULL);
        g_lang = CreateWindowW(L"BUTTON", L"EL / EN", WS_CHILD | WS_VISIBLE, 0, 0, 70, 28, hwnd, (HMENU)(INT_PTR)IDC_LANG, NULL, NULL);
        g_url = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
                                0, 0, 100, 28, hwnd, (HMENU)(INT_PTR)IDC_URL, NULL, NULL);
        g_analyze = CreateWindowW(L"BUTTON", L"Ανάλυση", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
                                  0, 0, 120, 32, hwnd, (HMENU)(INT_PTR)IDC_ANALYZE, NULL, NULL);
        for (int i = 0; i < 6; i++)
            CreateWindowW(L"BUTTON", EX_LABELS[i], WS_CHILD | WS_VISIBLE, 0, 0, 140, 26, hwnd, (HMENU)(INT_PTR)(IDC_EX0 + i), NULL, NULL);
        g_verdict = CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE, 0, 0, 100, 28, hwnd, (HMENU)(INT_PTR)IDC_VERDICT, NULL, NULL);
        g_meta = CreateWindowW(L"STATIC", L"Τοπική ανάλυση · ο σύνδεσμος δεν ανοίγεται. Επικολλήστε URL.",
                               WS_CHILD | WS_VISIBLE, 0, 0, 100, 40, hwnd, (HMENU)(INT_PTR)IDC_META, NULL, NULL);
        g_out = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY | WS_VSCROLL,
                                0, 0, 100, 100, hwnd, (HMENU)(INT_PTR)IDC_OUT, NULL, NULL);
        HWND title = g_title;
        SendMessageW(title, WM_SETFONT, (WPARAM)g_fontBig, TRUE);
        SendMessageW(g_url, WM_SETFONT, (WPARAM)g_font, TRUE);
        SendMessageW(g_analyze, WM_SETFONT, (WPARAM)g_font, TRUE);
        SendMessageW(g_lang, WM_SETFONT, (WPARAM)g_font, TRUE);
        SendMessageW(g_verdict, WM_SETFONT, (WPARAM)g_fontBig, TRUE);
        SendMessageW(g_meta, WM_SETFONT, (WPARAM)g_font, TRUE);
        SendMessageW(g_out, WM_SETFONT, (WPARAM)g_font, TRUE);
        for (int i = 0; i < 6; i++)
            SendMessageW(GetDlgItem(hwnd, IDC_EX0 + i), WM_SETFONT, (WPARAM)g_font, TRUE);
        SetFocus(g_url);
        return 0;
    }
    case WM_SIZE:
        layout(hwnd);
        return 0;
    case WM_CTLCOLORSTATIC: {
        HDC hdc = (HDC)wParam;
        SetBkColor(hdc, RGB(7, 9, 15));
        if ((HWND)lParam == g_verdict) SetTextColor(hdc, RGB(110, 168, 255));
        else SetTextColor(hdc, RGB(147, 160, 184));
        return (LRESULT)g_bg;
    }
    case WM_CTLCOLOREDIT: {
        HDC hdc = (HDC)wParam;
        SetBkColor(hdc, RGB(11, 15, 24));
        SetTextColor(hdc, RGB(232, 237, 247));
        return (LRESULT)g_edit;
    }
    case WM_COMMAND: {
        int id = LOWORD(wParam);
        if (id == IDC_ANALYZE || (id == IDC_URL && HIWORD(wParam) == EN_CHANGE && 0)) {
            /* analyze on button */
        }
        if (id == IDC_ANALYZE)
            do_analyze(hwnd);
        if (id == IDC_LANG) {
            g_el = !g_el;
            SetWindowTextW(g_analyze, g_el ? L"Ανάλυση" : L"Analyze");
        }
        if (id >= IDC_EX0 && id < IDC_EX0 + 6) {
            SetWindowTextW(g_url, EX_URLS[id - IDC_EX0]);
            do_analyze(hwnd);
        }
        return 0;
    }
    case WM_DESTROY:
        DeleteObject(g_bg); DeleteObject(g_edit); DeleteObject(g_font); DeleteObject(g_fontBig);
        if (g_bmp) DeleteObject(g_bmp);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

int WINAPI wWinMain(HINSTANCE hi, HINSTANCE hprev, LPWSTR cmd, int show) {
    (void)hprev; (void)cmd;
    set_exe_dir();
    INITCOMMONCONTROLSEX icc = {sizeof(icc), ICC_STANDARD_CLASSES};
    InitCommonControlsEx(&icc);
    WNDCLASSEXW wc = {0};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hi;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = CreateSolidBrush(RGB(7, 9, 15));
    wc.lpszClassName = L"PhishGuardWindow";
    wc.hIcon = LoadIconW(hi, MAKEINTRESOURCEW(1));
    wc.hIconSm = (HICON)LoadImageW(hi, MAKEINTRESOURCEW(1), IMAGE_ICON, 16, 16, 0);
    RegisterClassExW(&wc);
    HWND hwnd = CreateWindowExW(0, wc.lpszClassName, L"PhishGuard",
                                WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                                CW_USEDEFAULT, CW_USEDEFAULT, 980, 720,
                                NULL, NULL, hi, NULL);
    ShowWindow(hwnd, show);
    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0)) {
        if (msg.message == WM_KEYDOWN && msg.wParam == VK_RETURN && GetFocus() == g_url)
            do_analyze(hwnd);
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return (int)msg.wParam;
}
