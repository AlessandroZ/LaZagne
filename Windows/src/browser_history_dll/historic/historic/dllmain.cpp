#include <objbase.h>
#include <shlguid.h>
#include <stdio.h>
#include <urlhist.h>
#include <windows.h>

#pragma comment(lib, "ole32.lib")

#define URL_HISTORY_MAX 512
#include <string.h>

int GetUrlHistory(wchar_t **UrlHistory);
int GetUrlHistory(wchar_t **UrlHistory)
{
	int max = 0, len;
	wchar_t *p = NULL;
	IUrlHistoryStg2 *pUrlHistoryStg2 = NULL;
	IEnumSTATURL *pEnumUrls;
	STATURL StatUrl[1];
	ULONG ulFetched;
	HRESULT hr;
	CoInitialize(NULL);

	hr = CoCreateInstance(CLSID_CUrlHistory, NULL, CLSCTX_INPROC_SERVER,IID_IUrlHistoryStg2,(void**)(&pUrlHistoryStg2));
	if (SUCCEEDED(hr))
	{
		hr = pUrlHistoryStg2->EnumUrls(&pEnumUrls);
		if (SUCCEEDED(hr))
		{
			while (max < URL_HISTORY_MAX && (hr = pEnumUrls->Next(1,StatUrl, &ulFetched)) == S_OK)
			{
				if (StatUrl->pwcsUrl != NULL)
				{
					if (NULL != (p = wcschr(StatUrl->pwcsUrl,'?')))
						*p='\0';
					len = wcslen(StatUrl->pwcsUrl) + 1;
					UrlHistory[max] = new wchar_t[len];
					if (UrlHistory[max])
					{
						wcscpy_s(UrlHistory[max], len,  StatUrl->pwcsUrl);
						UrlHistory[max][len - 1] = '\0';
						max++;
					}
				}
			}
			pEnumUrls->Release();
		}
		pUrlHistoryStg2->Release();
	}
	CoUninitialize();
	return max;
}

extern "C" __declspec(dllexport) wchar_t** list()
{
	static wchar_t *UrlHistory[URL_HISTORY_MAX];
	GetUrlHistory(UrlHistory);
	return &UrlHistory[0];
}