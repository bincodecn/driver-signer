#include <windows.h>
#include <wincrypt.h>
#include <cryptuiapi.h>
#include <shlwapi.h>

#include <stdio.h>
#include <sys/stat.h>

#include "MinHook.h"

typedef void (*GetSystemTime_t)(LPSYSTEMTIME lpSystemTime);
typedef void (*GetLocalTime_t)(LPSYSTEMTIME lpSystemTime);
typedef LONG (*CertVerifyTimeValidity_t)(LPFILETIME pTimeToVerify, PCERT_INFO pCertInfo);

GetSystemTime_t GetSystemTimeOrigin = NULL;
GetLocalTime_t GetLocalTimeOrigin = NULL;
CertVerifyTimeValidity_t CertVerifyTimeValidityOrigin = NULL;

void WINAPI GetSystemTimeHook(LPSYSTEMTIME lpSystemTime)
{
    printf("GetSystemTimeHook\n");
    GetSystemTimeOrigin(lpSystemTime);
    lpSystemTime->wYear = 2011;
}

void WINAPI GetLocalTimeHook(LPSYSTEMTIME lpSystemTime)
{
    printf("GetLocalTimeHook\n");
    GetLocalTimeOrigin(lpSystemTime);
    lpSystemTime->wYear = 2011;
}

LONG WINAPI CertVerifyTimeValidityHook(LPFILETIME pTimeToVerify, PCERT_INFO pCertInfo) {
    printf("CertVerifyTimeValidityHook\n");
    return 0;
}

int HookSomeAPI()
{
    if (MH_Initialize() != MH_OK)
    {
        printf("Failed to initialize minhook\n");
        return -1;
    }

    return MH_CreateHook(GetSystemTime, GetSystemTimeHook, (LPVOID*)&GetSystemTimeOrigin) ||
            MH_CreateHook(GetLocalTime, GetLocalTimeHook, (LPVOID*)&GetLocalTimeOrigin) ||
            MH_CreateHook(CertVerifyTimeValidity, CertVerifyTimeValidityHook, (LPVOID*)&CertVerifyTimeValidityOrigin) ||
            MH_EnableHook(GetSystemTime) ||
            MH_EnableHook(GetLocalTime) ||
            MH_EnableHook(CertVerifyTimeValidity);
}

BOOL SignDriver(LPVOID PfxBuffer, DWORD PfxBufferSize, LPWSTR Password, LPWSTR InputFile)
{
	CRYPT_DATA_BLOB PfxBlob;
	HCERTSTORE CertStore;
	PCCERT_CONTEXT CertContext;
	CRYPTUI_WIZ_DIGITAL_SIGN_INFO SignInfo;
	CRYPTUI_WIZ_DIGITAL_SIGN_EXTENDED_INFO SignExtInfo;
	DWORD key_size;
	PCRYPT_KEY_PROV_INFO key;
	HCRYPTPROV provider;

	PfxBlob.cbData = PfxBufferSize;
	PfxBlob.pbData = PfxBuffer;
	CertStore = PFXImportCertStore(&PfxBlob, Password, 0);

	if (!CertStore) {
		printf("Failed to import pfx %x\n", GetLastError());
        goto CLEAN;
    }

	CertContext = CertEnumCertificatesInStore(CertStore, NULL);

	if (!CertContext)
	{
        printf("Failed to get certificates context\n");
		goto CLEAN;
	}

	memset(&SignInfo, 0, sizeof(SignInfo));
	SignInfo.dwSize = sizeof(SignInfo);
	SignInfo.dwSubjectChoice = CRYPTUI_WIZ_DIGITAL_SIGN_SUBJECT_FILE;
	SignInfo.pwszFileName = InputFile;
	SignInfo.dwSigningCertChoice = CRYPTUI_WIZ_DIGITAL_SIGN_CERT;
	SignInfo.pSigningCertContext = CertContext;
	//SignInfo.pwszTimestampURL = L"http://timestamp.verisign.com/scripts/timstamp.dll";
	//SignInfo.dwAdditionalCertChoice = CRYPTUI_WIZ_DIGITAL_SIGN_ADD_CHAIN;
	SignInfo.pSignExtInfo = &SignExtInfo;

	memset(&SignExtInfo, 0, sizeof(SignExtInfo));
	SignExtInfo.dwSize = sizeof(SignExtInfo);
	SignExtInfo.hAdditionalCertStore = CertStore;

    if (!CryptUIWizDigitalSign(CRYPTUI_WIZ_NO_UI, NULL, NULL, &SignInfo, NULL)) {
        printf("Failed to sign driver %x\n", GetLastError());
        goto CLEAN;
    }

CLEAN:
    if (CertContext)
        CertFreeCertificateContext(CertContext);
    if (CertStore)
        CertCloseStore(CertStore, 0);
	return TRUE;
}

VOID PrintUsage()
{
    printf("driver-signer -p password -f input.pfx input.sys\n");
    printf("-p password\tif not set, will be asked later. optional\n");
    printf("-f input.pfx\tthe pfx file. required");
}

int wmain(int wargc, LPWSTR wargv[])
{
    int wargi = 1;
    WCHAR PasswordBuffer[128];
    LPWSTR Password = NULL;
    LPWSTR PfxFile = NULL;
    LPWSTR InputFile = NULL;

    while(wargi < wargc) {
        switch(wargv[wargi][0]) {
            case '-':
                switch(wargv[wargi][1]) {
                    case 'p':
                        Password = wargv[wargi + 1];
                        wargi ++;
                        break;
                    case 'f':
                        PfxFile = wargv[wargi + 1];
                        wargi ++;
                        break;
                    default:
                        wprintf(L"Unknown option %c\n", wargv[wargi][1]);
                        PrintUsage();
                        exit(-1);
                }
                break;
            default:
                if (!InputFile) {
                    InputFile = wargv[wargi];
                } else {
                    wprintf(L"Unknown option %c\n", wargv[wargi][1]);
                    PrintUsage();
                    exit(-1);
                }
                break;
        }
        wargi ++;
    }

    if (!InputFile) {
        wprintf(L"Missing input file\n");
        PrintUsage();
        exit(-1);
    }

    if (!Password) {
        wprintf(L"Password: ");
        fflush(stdout);
        fgetws(PasswordBuffer, 128, stdin);
        Password = PasswordBuffer;
    }

    if (HookSomeAPI()) {
        printf("Hook failed\n");
        exit(-1);
    }

    struct stat st;

    if (wstat(PfxFile, &st)) {
        printf("Can not access pfx file\n");
        return -1;
    }

    PVOID PfxBuffer = malloc(st.st_size);
    if (!PfxBuffer) {
        printf("Out of memory\n");
        return -1;
    }

    FILE *ifp = _wfopen(PfxFile, L"rb");

    if (!ifp) {
        printf("Failed to open input file.\n");
        free(PfxBuffer);
        return -1;
    }

    fread(PfxBuffer, st.st_size, 1, ifp);
    fclose(ifp);

    SignDriver(PfxBuffer, st.st_size, Password, InputFile);

    free(PfxBuffer);

	return 0;
}

int main(int argc, const char *argv[])
{
    int wargc = 0;
    LPWSTR* wargv = CommandLineToArgvW(GetCommandLineW(), &wargc);
    return wmain(wargc, wargv);
}
