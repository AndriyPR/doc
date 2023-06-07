ДОДАТОК І
ВХІДНІ ТА ВИХІДНІ ДАНІ (ІНТЕРФЕЙС ПРОГРАМУВАННЯ) НА МОВІ PYTHON
І.1 Інтерфейс програмування
Опис інтерфейсу бібліотеки наведений у файлі EUSignCP.py. Файл _EUSignCP.pyd містить скомпільований код для роботи з бібліотекою підпису на мові.
Бібліотека завантажується та звільняється за допомогою функцій EULoad та EUUnload:
	// Функція завантаження бібліотеки. Повертає TRUE у разі успіху, та FALSE, якщо 
	// виникає помилка
def EULoad() -> Boolean
	// Функція звільнення бібліотеки
def EUUnload()
Формальний опис інтерфейсу програмування бібліотеки наведений на мові Python.
Інтерфейс програмування бібліотеки представлений у вигляді класу  EU_INTERFACE, яка містить доступні функції роботи з бібліотекою. Отримати інтерфейс бібліотеки, можна за допомогою функції EUGetInterface:
	// Функція отримання інтерфейсу бібліотеки. Повертає інтерфейс бібліотеки, або 
	// NULL, якшо бібліотеку не завантажено.
def EUGetInterface() -> EU_INTERFACE
	// Функції, що реалізує бібліотека
	class EU_INTERFACE(_object)
		def Initialize(self)

		def IsInitialized(self)

		def Finalize(self)

		def ReadPrivateKey(self, pKeyMedia, pInfo)

		def IsPrivateKeyReaded(self)

		def ResetPrivateKey(self)

		def SignData(self, pbData, dwDataLength, ppszSign, ppbSign)

		def VerifyData(self, pbData, dwDataLength, pszSign, pbSign, dwSignLength, pSignInfo)

		def SignDataInternal(self, bAppendCert, pbData, dwDataLength, ppszSignedData, ppbSignedData)

		def VerifyDataInternal(self, pszSignedData, pbSignedData, dwSignedDataLength, ppbData, pSignInfo)

		def HashData(self, pbData, dwDataLength, ppszHash, ppbHash)

		def HashDataContinue(self, pbData, dwDataLength)

		def HashDataEnd(self, ppszHash, ppbHash)

		def HashFile(self, pszFileName, ppszHash, ppbHash)

		def SignHash(self, pszHash, pbHash, dwHashLength, ppszSign, ppbSign)

		def VerifyHash(self, pszHash, pbHash, dwHashLength, pszSign, pbSign, dwSignLength, pSignInfo)

		def EnumKeyMediaTypes(self, dwTypeIndex, pszTypeDescription)

		def EnumKeyMediaDevices(self,Read dwTypeIndex, dwDeviceIndex, pszDeviceDescription)

		def GetFileStoreSettings(self, pszPath)

		def RawSignData(self, pbData, dwDataLength, ppszSign, ppbSign)

		def RawVerifyData(self, pbData, dwDataLength, pszSign, pbSign, dwSignLength, pSignInfo)

		def RawSignHash(self, pszHash, pbHash, dwHashLength, ppszSign, ppbSign)

		def RawVerifyHash(self, pszHash, pbHash, dwHashLength, pszSign, pbSign, dwSignLength, pInfo)

		def RawSignFile(self, pszFileName, pszFileNameWithSign)

		def RawVerifyFile(self, pszFileNameWithSign, pszFileName, pSignInfo)

		def DevelopData(self, pszEnvelopedData, pbEnvelopedData, dwEnvelopedDataLength, ppbData, pInfo)

		def ReadPrivateKeyBinary(self, pbPrivateKey, dwPrivateKeyLength, pszPassword, pInfo)

		def ReadPrivateKeyFile(self, pszPrivateKeyFileName, pszPassword, pInfo)

		def SessionDestroy(self, pvSession)

		def ClientSessionCreateStep1(self, dwExpireTime, ppvClientSession, ppbClientData)

		def ServerSessionCreateStep1(self, dwExpireTime, pbClientData, dwClientDataLength, ppvServerSession, ppbServerData)

		def ClientSessionCreateStep2(self, pvClientSession, pbServerData, dwServerDataLength, ppbClientData)

		def ServerSessionCreateStep2(self, pvServerSession, pbClientData, dwClientDataLength)

		def SessionIsInitialized(self, pvSession)

		def SessionSave(self, pvSession, ppbSessionData)

		def SessionLoad(self, pbSessionData, dwSessionDataLength, ppvSession)

		def SessionCheckCertificates(self, pvSession)

		def SessionEncrypt(self, pvSession, pbData, dwDataLength, ppbEncryptedData)

		def SessionDecrypt(self, pvSession, pbEncryptedData, dwEncryptedDataLength, ppbData)

		def SessionGetPeerCertificateInfo(self, pvSession, pInfo)

		def DevelopFile(self, pszEnvelopedFileName, pszFileName, pInfo)

		def GetCertificateInfoEx(self, pszIssuer, pszSerial, ppInfo)

		def GetCRInfo(self, pbRequest, dwRequest, ppInfo)

		def GetSignsCount(self, pszSign, pbSign, dwSignLength, pdwCount)

		def GetSignerInfo(self, dwSignIndex, pszSign, pbSign, dwSignLength, ppInfo, ppbCertificate)

		def HashDataWithParams(self, pbCertificate, dwCertificateLength, pbData, dwDataLength, ppszHash, ppbHash)

		def HashDataBeginWithParams(self, pbCertificate, dwCertificateLength)

		def HashFileWithParams(self, pbCertificate, dwCertificateLength, pszFileName, ppszHash, ppbHash)

		def EnvelopDataToRecipients(self, dwRecipientCerts, bSignData, pbData, dwDataLength, ppszEnvelopedData, ppbEnvelopedData)

		def EnvelopFileToRecipients(self, dwRecipientCerts, bSignData, pszFileName, pszEnvelopedFileName)

		def ParseCertificateEx(self, pbCertificate, dwCertificateLength, ppInfo)

		def ClientDynamicKeySessionCreate(self, dwExpireTime, pszServerCertIssuer, pszServerCertSerial, pbServerCert, dwServerCertLength, ppvClientSession, ppbClientData)

		def ServerDynamicKeySessionCreate(self, dwExpireTime, pbClientData, dwClientDataLength, ppvServerSession)

		def VerifyHashOnTimeEx(self, pszHash, pbHash, dwHashLength, dwSignIndex, pszSign, pbSign, dwSignLength, pOnTime, bOffline, bNoCRL, pInfo)

		def VerifyDataOnTimeEx(self, pbData, dwDataLength, dwSignIndex, pszSign, pbSign, dwSignLength, pOnTime, bOffline, bNoCRL, pInfo)

		def VerifyDataInternalOnTimeEx(self, dwSignIndex, pszSignedData, pbSignedData, dwSignedDataLength, pOnTime, bOffline, bNoCRL, ppbData, pInfo)

		def EnvelopDataToRecipientsOffline(self, dwRecipientCerts, bSignData, pbData, dwDataLength, bOffline, bNoCRL, ppszEnvelopedData, ppbEnvelopedData)

		def GeneratePRNGSequence(self, pbData, dwDataLength) 

		def SetFileStoreSettings(self, pszPath) 

		def GetProxySettings(self, pbUseProxy) 

		def SetProxySettings(self, bUseProxy) 

		def GetOCSPSettings(self, pbUseOCSP) 

		def SetOCSPSettings(self, bUseOCSP) 

		def GetTSPSettings(self, pbGetStamps) 

		def SetTSPSettings(self, bGetStamps) 

		def GetLDAPSettings(self, pbUseLDAP) 

		def SetLDAPSettings(self, bUseLDAP) 

		def GetCMPSettings(self, pbUseCMP) 

		def SetCMPSettings(self, bUseCMP) 

		def DoesNeedSetSettings(self) 

		def GetModeSettings(self, pbOfflineMode) 

		def SetModeSettings(self, bOfflineMode) 

		def GetOCSPAccessInfoModeSettings(self, pbEnabled) 

		def SetOCSPAccessInfoModeSettings(self, bEnabled) 

		def EnumOCSPAccessInfoSettings(self, dwIndex, pszIssuerCN) 

		def GetOCSPAccessInfoSettings(self, pszIssuerCN) 

		def SetOCSPAccessInfoSettings(self, pszIssuerCN) 

		def DeleteOCSPAccessInfoSettings(self, pszIssuerCN)

		def EnvelopDataExWithDynamicKey(self, pszRecipientCertIssuers, pszRecipientCertSerials, bSignData, bAppendCert, pbData, dwDataLength, ppszEnvelopedData, ppbEnvelopedData

		def EnvelopDataToRecipientsWithDynamicKey(self, dwRecipientCerts, bSignData, bAppendCert, pbData, dwDataLength, ppszEnvelopedData, ppbEnvelopedData)

		def EnvelopFileExWithDynamicKey(self, pszRecipientCertIssuers, pszRecipientCertSerials, bSignData, bAppendCert, pszFileName, pszEnvelopedFileName)

		def EnvelopFileToRecipientsWithDynamicKey(self, dwRecipientCerts, bSignData, bAppendCert, pszFileName, pszEnvelopedFileName)

		def SetUIMode(self, bUIMode)

		def GetDataFromSignedData(self, pszSignedData, pbSignedData, dwSignedDataLength, ppbData)

		def SetRuntimeParameter(self, pszParameterName, pvParameterValue)

		def IsDataInSignedDataAvailable(self, pszSignedData, pbSignedData, dwSignedDataLength, pbAvailable)

		def IsDataInSignedFileAvailable(self, pszFileNameWithSignedData, pbAvailable)

		def CreateEmptySign(self, pbData, dwDataLength, ppszSign, ppbSign) 

		def AppendSigner(self, pszSigner, pbSigner, dwSignerLength, pbCertificate, dwCertificateLength, pszPreviousSign, pbPreviousSign, dwPreviousSignLength, ppszSign, ppbSign) 

		def GetSigner(self, dwSignIndex, pszSign, pbSign, dwSignLength, ppszSigner, ppbSigner) 

		def GetFileSigner(self, dwSignIndex, pszFileNameWithSign, ppszSigner, ppbSigner) 

		def GetFileSignsCount(self, pszFileNameWithSign, pdwCount) 

		def GetFileSignerInfo(self, dwSignIndex, pszFileNameWithSign, ppInfo, ppbCertificate) 

		def CtxCreate(self, ppvContext) 

		def CtxFree(self, pvContext) 

		def CtxCreateEmptySignFile(self, pvContext, dwSignAlgo, pszFileName, pbCertificate, dwCertificateLength, pszFileNameWithSign) 

		def CtxAppendSignerFile(self, pvContext, dwSignAlgo, pbSigner, dwSignerLength, pbCertificate, dwCertificateLength, pszFileNameWithPreviousSign, pszFileNameWithSign)

		def GetCertificate(self, pszIssuer, pszSerial, ppszCertificate, ppbCertificate) 

		def EnumOwnCertificates(self, dwIndex, ppInfo) 

		def GetSenderInfo(self, pszEnvelopedData, pbEnvelopedData, dwEnvelopedDataLength, pbRecipientCert, dwRecipientCertLength, pbDynamicKey, ppInfo, ppbCertificate) 

		def GetFileSenderInfo(self, pszEnvelopedFileName, pbRecipientCert, dwRecipientCertLength, pbDynamicKey, ppInfo, ppbCertificate) 

		def GetRecipientsCount(self, pszEnvelopedData, pbEnvelopedData, dwEnvelopedDataLength, pdwCount) 

		def GetFileRecipientsCount(self, pszEnvelopedFileName, pdwCount) 

		def GetRecipientInfo(self, dwRecipientIndex, pszEnvelopedData, pbEnvelopedData, dwEnvelopedDataLength, pdwRecipientInfoType, ppszRecipientIssuer, ppszRecipientSerial, ppszRecipientPublicKeyID) 

		def GetFileRecipientInfo(self, dwRecipientIndex, pszEnvelopedFileName, pdwRecipientInfoType, ppszRecipientIssuer, ppszRecipientSerial, ppszRecipientPublicKeyID) 

		def CtxIsNamedPrivateKeyExists(self, pvContext, pKeyMedia, pszNamedPrivateKeyLabel, pszNamedPrivateKeyPassword, pbExists)

		def CtxGenerateNamedPrivateKey(self, pvContext, pKeyMedia, pszNamedPrivateKeyLabel, pszNamedPrivateKeyPassword, dwUAKeysType, dwUADSKeysSpec, dwUAKEPKeysSpec, pszUAParamsPath, dwInternationalKeysType, dwInternationalKeysSpec, pszInternationalParamsPath, ppbUARequest, pszUAReqFileName, ppbUAKEPRequest, pszUAKEPReqFileName, ppbInternationalRequest, pszInternationalReqFileName)

		def CtxReadNamedPrivateKey(self, pvContext, pKeyMedia, pszNamedPrivateKeyLabel, pszNamedPrivateKeyPassword, ppvPrivateKeyContext, pInfo)

		def CtxDestroyNamedPrivateKey(self, pvContext, pKeyMedia, pszNamedPrivateKeyLabel, pszNamedPrivateKeyPassword)

		def CtxChangeNamedPrivateKeyPassword(self, pvContext, pKeyMedia, pszNamedPrivateKeyLabel, pszNamedPrivateKeyPassword, pszNamedPrivateKeyNewPassword)

		def CtxFreePrivateKey(self, pvPrivateKeyContext)

		def CtxSignHashValue(self, pvPrivateKeyContext, dwSignAlgo, pbHash, dwHashLength, bAppendCert, ppbSign)

		def CtxSignData(self, pvPrivateKeyContext, dwSignAlgo, pbData, dwDataLength, bExternal, bAppendCert, ppbSign)

		def CtxGenerateNamedPrivateKeyEx(self, pvContext, pKeyMedia, pszNamedPrivateKeyLabel, pszNamedPrivateKeyPassword, dwUAKeysType, dwUADSKeysSpec, dwUAKEPKeysSpec, pszUAParamsPath, dwInternationalKeysType, dwInternationalKeysSpec, pszInternationalParamsPath, pUserInfo, pszExtKeyUsages, ppbUARequest, pszUAReqFileName, ppbUAKEPRequest, pszUAKEPReqFileName, ppbInternationalRequest, pszInternationalReqFileName) 

		def CtxReadPrivateKey(self, pvContext, pKeyMedia, ppvPrivateKeyContext, pInfo)

		def CtxReadPrivateKeyBinary(self, pvContext, pbPrivateKey, dwPrivateKeyLength, pszPassword, ppvPrivateKeyContext, pInfo)

		def CtxMakeDeviceCertificate(self, pvPrivateKeyContext, pszDeviceName, pbUARequest, dwUARequestLength, pbUAKEPRequest, dwUAKEPRequestLength, pbInternationalRequest, dwInternationalRequestLength, pbECDSARequest, dwECDSARequestLength, pszCMPAddress, pszCMPPort, ppbUACertificate, ppbUAKEPCertificate, ppbInternationalCertificate, ppbECDSACertificate) 

		def CtxEnvelopData(self, pvPrivateKeyContext, dwRecipientCerts, dwRecipientAppendType, bSignData, bAppendCert, pbData, dwDataLength, ppbEnvelopedData)

		def CtxDevelopData(self, pvPrivateKeyContext, pszEnvelopedData, pbEnvelopedData, dwEnvelopedDataLength, pbSenderCert, dwSenderCertSize, ppbData, pInfo)

		def CtxGetOwnCertificate(self, pvPrivateKeyContext, dwCertKeyType, dwKeyUsage, ppInfo, ppbCertificate)

		def AppendTransportHeader(self, pszCAType, pszFileName, pszClientEMail, pbClientCert, dwClientCertLength, pbCryptoData, dwCryptoDataLength, ppbTransportData)

		def ParseTransportHeader(self, pbTransportData, dwTransportDataLength, pdwReceiptNumber, ppbCryptoData)

		def AppendCryptoHeader(self, pszCAType, dwHeaderType, pbCryptoData, dwCryptoDataLength, ppbTransportData)

		def ParseCryptoHeader(self, pbTransportData, dwTransportDataLength, pszCAType, pdwHeaderType, pdwHeaderSize, ppbCryptoData)

Завантаження та вивантаження бібліотеки відбувається за допомогою функцій EULoad() та EUUnload(). Інтерфейс роботи з бібліотекою може бути отриманий за допомогою функції EUGetInterface().

І.2 Коди помилок
Функції у разі успішного виконання повертають результат виконання операції, а у разі виникнення помилки генерують виняток (exception) з описом помилки. Опис помилок та можливі причини виникнення наведені у табл. І.1
Таблиця І.1 – Опис помилок та можливі причини виникнення
Найменування	Опис	Можливі причини виникнення
EU_ERROR_UNKNOWN	Невідома помилка	Відмова бібліотеки
EU_ERROR_NOT_SUPPORTED	Бібліотеку не ініціалізовано	Не був викликаний метод Initialize
		
EU_ERROR_NOT_INITIALIZED	Операція не підтримується	
EU_ERROR_BAD_PARAMETER	Невірний параметр	Переданий у виклик метода параметр має невірний формат
EU_ERROR_LIBRARY_LOAD	Виникла помилка при завантаженні базових бібліотек	Одна з базових бібліотек не завантажена або виникла помилка при її ініціалізації
EU_ERROR_READ_SETTINGS	Виникла помилка при зчитуванні параметрів з системного реєстру	Параметри не встановлені або пошкоджені чи переданий неправильний шлях їх розміщення у системному реєстрі
EU_ERROR_TRANSMIT_REQUEST	Виникла помилка при передачі запиту на сервер ЦСК за протоколом HTTP	Сервер ЦСК не доступний (проблеми з комунікаційними засобами) або не пройдено автентифікацію на proxy-сервері
EU_ERROR_MEMORY_ALLOCATION	Виникла помилка при виділенні пам'яті	
EU_WARNING_END_OF_ENUM	Перелічення закінчено	Не є помилкою. Повідомляє про завершення списку переліку.
EU_ERROR_PROXY_NOT_AUTHORIZED	Автентифікація на proxy-сервері не можлива	Параметри автентифікації на proxy-сервері не встановлені в реєстрі або автентифікацію не пройдено
EU_ERROR_NO_GUI_DIALOGS	Діалог з оператором не підтримується	Виникла необхідність виведення діалогу з оператором який не підтримується
EU_ERROR_DOWNLOAD_FILE	Виникла помилка при завантаженні файлу з HTTP-сервера	Сервер ЦСК не доступний (проблеми з комунікаційними засобами) або не пройдено автентифікацію на proxy-сервері
EU_ERROR_WRITE_SETTINGS	Виникла помилка при записі параметрів у системний реєстр	
EU_ERROR_CANCELED_BY_GUI	Операція відмінена оператором	Не виникає за відсутності діалогів з оператором
EU_ERROR_OFFLINE_MODE	Доступ до сервера ЦСК не можливий (увімкнено offline-режим)	
		
EU_ERROR_KEY_MEDIAS_FAILED	Виникла помилка при роботі з носіями ключової інформації	Відмова бібліотеки роботи з НКІ
EU_ERROR_KEY_MEDIAS_ACCESS_FAILED	Виникла помилка при доступі до носія ключової інформації	Не пройдено автентифікацію на НКІ або НКІ нероботоспроможний
EU_ERROR_KEY_MEDIAS_READ_FAILED	Виникла помилка при зчитуванні особистого ключа з носія ключової інформації	Особистий ключ на НКІ відсутній або пошкоджений
EU_ERROR_KEY_MEDIAS_WRITE_FAILED	Виникла помилка при записі особистого ключа на носій ключової інформації	
EU_WARNING_KEY_MEDIAS_READ_ONLY	Носій ключової інформації не підтримує знищення даних	
EU_ERROR_KEY_MEDIAS_DELETE	Виникла помилка при видаленні особистого ключа з носія ключової інформації	
EU_ERROR_KEY_MEDIAS_CLEAR	Виникла помилка при очищенні носія ключової інформації	
EU_ERROR_BAD_PRIVATE_KEY	Виникла помилка при відкритті особистого ключа (невірний пароль чи ключ пошкоджений)	Особистий ключ зчитаний з носія або пошкоджений або вказано невірний пароль його захисту
		
EU_ERROR_PKI_FORMATS_FAILED	Виникла помилка при розборі даних (пошкоджені дані чи невірний формат)	В залежності від контексту операції – пошкоджений підпис чи зашифровані дані
EU_ERROR_CSP_FAILED	Виникла помилка при виконанні криптоперетворень	Дані пошкоджені. Рівень пошкодження не виявлений при розборі формату даних
EU_ERROR_BAD_SIGNATURE	Невірний підпис	Підписані дані модифіковано або модифіковано сам підпис
EU_ERROR_AUTH_FAILED	Виникла помилка при автентифікації (дані автентифікації пошкоджені)	Дані автентифікації пошкоджені
EU_ERROR_NOT_RECEIVER	Власник особистого ключа відсутній у списку одержувачів зашифрованих даних	Користувач-власник проточного зчитаного особистого ключа не може розшифрувати дані, тому що вони були зашифровані на іншого користувача
		
EU_ERROR_STORAGE_FAILED	Виникла помилка при роботі з файловим сховищем сертифікатів та СВС	Не вірно вказаний каталог файлового сховища або каталог не існує 
EU_ERROR_BAD_CERT	Сертифікат пошкоджений	Сертифікат пошкоджений або має не вірний формат
EU_ERROR_CERT_NOT_FOUND	Сертифікат не знайдено	Сертифікат не знайдено жодними з доступних засобів. Послідовність пошуку – файлове сховище, протокол OCSP, LDAP-каталог
EU_ERROR_INVALID_CERT_TIME	Сертифікат не чинний за строком дії	Строк чинності сертифіката вже завершився або ще не наступив
EU_ERROR_CERT_IN_CRL	Сертифікат не чинний (при перевірці за допомогою СВС)	Сертифікат заблокований чи скасований 
EU_ERROR_BAD_CRL	СВС пошкоджений	Один з СВС у ланцюжку пошкоджений або має не вірний формат
EU_ERROR_NO_VALID_CRLS	Не знайдено діючих СВС	У файловому сховищі не знайдено діючих СВС
		
EU_ERROR_GET_TIME_STAMP	Виникла помилка при отриманні позначки часу	TSP-сервер не доступний (проблеми з комунікаційними засобами) або не пройдено автентифікацію на proxy-сервері
EU_ERROR_BAD_TSP_RESPONSE	Відповідь від TSP-сервера пошкоджена	
EU_ERROR_TSP_SERVER_CERT_NOT_FOUND	Сертифікат TSP-сервера не знайдено	Сертифікат TSP-сервера, яким підписано отриману позначку часу  не знайдено у файловому сховищі
EU_ERROR_TSP_SERVER_CERT_INVALID	Сертифікат TSP-сервера не чинний	Сертифікат TSP-сервера, яким підписано отриману позначку часу не чинний
		
EU_ERROR_GET_OCSP_STATUS	Виникла помилка при спробі отримати статус сертифіката за протоколом OCSP	OCSP-сервер не доступний (проблеми з комунікаційними засобами) або не пройдено автентифікацію на proxy-сервері
EU_ERROR_BAD_OCSP_RESPONSE	Відповідь від OCSP-сервера пошкоджена	
EU_ERROR_CERT_BAD_BY_OCSP	Сертифікат не чинний (при перевірці за протоколом OCSP)	Сертифікат, статус якого визначався за допомогою протоколу OCSP
EU_ERROR_OCSP_SERVER_CERT_NOT_FOUND	Сертифікат OCSP-сервера не знайдено	Сертифікат OCSP-сервера, яким підписано інформацію про статус сертифіката не знайдено у файловому сховищі
EU_ERROR_OCSP_SERVER_CERT_INVALID	Сертифікат OCSP-сервера не чинний	Сертифікат OCSP-сервера, яким підписано інформацію про статус сертифіката не чинний
		
EU_ERROR_LDAP_ERROR	Виникла помилка при роботі з LDAP-сервером	LDAP-сервер не доступний (проблеми з комунікаційними засобами)

І.3 Константи
	// Макс. Довжина строки з описом помилки
	 EU_ERROR_MAX_LENGTH			1025	// Макс. довжина строки із 
									// описом помилки враховуючи
									// символ кінця строки

	// Макс. довжини параметрів структури EU_KEY_MEDIA
	 EU_PASS_MAX_LENGTH			65	// Макс. довжина строки з
									// паролем доступу до носія
									// особистого ключа враховуючи
									// символ кінця строки
	 EU_KEY_MEDIA_NAME_MAX_LENGTH	257	// Макс. довжина строки із 
									// описом типу або назви НКІ
									// враховуючи символ кінця
									// строки

	// Макс. довжини параметрів
	 EU_ISSUER_MAX_LENGTH			1024	// Макс. довжина строки із 
									// описом емітента не 
									// враховуючи символ кінця 
									// строки
	 EU_SERIAL_MAX_LENGTH 			64	// Макс. довжина строки із 
									// серійного номеру сертифіката 
									// не враховуючи символ кінця 
									// строки

	// Спосіб отримання параметрів НКІ
	 EU_KEY_MEDIA_SOURCE_TYPE_OPERATOR	1	// Запитувати параметри НКІ у
									// оператора
	 EU_KEY_MEDIA_SOURCE_TYPE_FIXED 	2	// Використовувати фіксовані 
									// параметри НКІ

	// Версії структур з інформацією повертаємих бібліотекою
	 EU_CERT_INFO_VERSION			1	// Версія структури з детальною
									// інформацією про сертифікат
	 EU_CERT_INFO_EX_VERSION		5	// Версія структури з 
									// розширеною інформацією про
									// сертифікат
	 EU_CRL_DETAILED_INFO_VERSION	1	// Версія структури з детальною
									// інформацією про СВС
	 EU_CR_INFO_VERSION			3	// Версія структури з 
									// інформацією про запит на 
									// отримання сертифіката
	 EU_USER_INFO_VERSION			3	// Версія структури з 
									// інформацією про користувача
	 EU_TIME_INFO_VERSION			1	// Версія структури з 
									// інформацією про час

	// Макс. довжини параметрів структури EU_USER_INFO
	 EU_PATH_MAX_LENGTH			1041	// Макс. довжина строки із
									// шляхом до файла враховуючи
									// символ кінця строки
	 EU_COMMON_NAME_MAX_LENGTH		65	// Макс. довжина реквізиту 
									// сертифіката "повне 
									// найменування організації" 
									// ("commonName") враховуючи
									// символ кінця строки
	 EU_LOCALITY_MAX_LENGTH		129	// Макс. довжина реквізиту 
									// сертифіката "Назва 
									// населеного пункту" 
									// ("SubjLocality") враховуючи
									// символ кінця строки
	 EU_STATE_MAX_LENGTH			129	// Макс. довжина реквізиту 
									// сертифіката " Назва області" 
									// ("SubjState") враховуючи
									// символ кінця строки
	 EU_ORGANIZATION_MAX_LENGTH		65	// Макс. довжина реквізиту 
									// сертифіката "Назва
									// організації" ("SubjOrg ")
									// враховуючи символ кінця
									// строки
	 EU_ORG_UNIT_MAX_LENGTH		65	// Макс. довжина реквізиту 
									// сертифіката "Назва
									// підрозділу організації" 
									// ("SubjOrg ") враховуючи
									// символ кінця строки
	 EU_TITLE_MAX_LENGTH			65	// Макс. довжина реквізиту 
									// сертифіката "Посада" 
									// ("SubjTitle ") враховуючи
									// символ кінця строки
	 EU_STREET_MAX_LENGTH			129	// Макс. довжина реквізиту 
									// сертифіката "Назва вулиці" 
									// ("SubjStreet") враховуючи
									// символ кінця строки
	 EU_PHONE_MAX_LENGTH			33	// Макс. довжина реквізиту 
									// сертифіката "Номер телефону" 
									// ("SubjPhone ") враховуючи
									// символ кінця строки
	 EU_SURNAME_MAX_LENGTH			41	// Макс. довжина реквізиту 
									// сертифіката "Прізвище" 
									// ("SubjSurname") враховуючи
									// символ кінця строки
	 EU_GIVENNAME_MAX_LENGTH		33	// Макс. довжина реквізиту 
									// сертифіката "Ім'я 
									// по-батькові" 
									// ("SubjGivenName") враховуючи
									// символ кінця строки
	 EU_EMAIL_MAX_LENGTH			129	// Макс. довжина реквізиту 
									// сертифіката "Адреса 
									// електронної пошти" 
									// ("SubjEmail") враховуючи
									// символ кінця строки
	 EU_ADDRESS_MAX_LENGTH			257	// Макс. довжина реквізиту 
									// сертифіката "DNS-ім’я" 
									// ("dNSName") враховуючи
									// символ кінця строки
	 EU_EDRPOU_MAX_LENGTH			11	// Макс. довжина реквізиту 
									// сертифіката "Код ЄДРПОУ" 
									// ("SubjEDRPOUCode")
									// враховуючи символ кінця
									// строки
	 EU_DRFO_MAX_LENGTH			11	// Макс. довжина реквізиту 
									// сертифіката "Код ДРФО" 
									// ("SubjDRFOCode") враховуючи
									// символ кінця строки
	 EU_NBU_MAX_LENGTH			7	// Макс. довжина реквізиту 
									// сертифіката "Ідентифікатор 
									// НБУ" ("SubjNBUCode")
									// враховуючи символ кінця
									// строки
	 EU_SPFM_MAX_LENGTH			7	// Макс. довжина реквізиту 
									// сертифіката "Ідентифікатор 
									// СПФМ" ("SubjSPFMCode")
									// враховуючи символ кінця
									// строки
	 EU_O_CODE_MAX_LENGTH			33	// Макс. довжина реквізиту 
									// сертифіката "Код 
									// організації" ("SubjOCode")
									// враховуючи символ кінця
									// строки
	 EU_OU_CODE_MAX_LENGTH			33	// Макс. довжина реквізиту 
									// сертифіката "Код підрозділу 
									// організації" ("SubjOUCode")
									// враховуючи символ кінця
									// строки
	 EU_USER_CODE_MAX_LENGTH		33	// Макс. довжина реквізиту 
									// сертифіката "Код 
									// користувача" 
									// ("SubjUserCode") враховуючи
									// символ кінця строки
	 EU_UPN_MAX_LENGTH			257	// Макс. довжина реквізиту 
									// сертифіката "UPN-ім'я" 
									// ("UPN") враховуючи символ
									// кінця строки
	 EU_PORT_MAX_LENGTH			6	// Макс. довжина строки із 
									// значенням порту підключення
	 EU_USER_NAME_MAX_LENGTH		65	// Макс. довжина строки із 
									// ім’ям користувача враховуючи 
									// символ кінця строки
	 EU_UNZR_MAX_LENGTH			15	// Макс. довжина строки із 
									// номером УНЗР враховуючи
									// символ кінця строки
	 EU_COUNTRY_MAX_LENGTH			3	// Макс. довжина строки із 
									// кодом країни враховуючи 
									// символ кінця строки

	// Типи власників сертифікатів
	 EU_SUBJECT_TYPE_UNDIFFERENCED	0	// Тип власника сертифіката 
									// не визначено
	 EU_SUBJECT_TYPE_CA			1	// Тип власника сертифіката ЦСК
	 EU_SUBJECT_TYPE_CA_SERVER		2	// Тип власника сертифіката 
									// сервер ЦСК
	 EU_SUBJECT_TYPE_RA_ADMINISTRATOR	3	// Тип власника сертифіката 
									// адміністратор реєстрації
	 EU_SUBJECT_TYPE_END_USER		4	// Тип власника сертифіката
									// кінцевий користувач

	// Типи власників сертифікатів серверів ЦСК
	 EU_SUBJECT_CA_SERVER_SUB_TYPE_UNDIFFERENCED	0 // Тип сервера не 
										  // визначено
	 EU_SUBJECT_CA_SERVER_SUB_TYPE_CMP			1 // CMP-сервер ЦСК
	 EU_SUBJECT_CA_SERVER_SUB_TYPE_TSP			2 // TSP-сервер ЦСК
	 EU_SUBJECT_CA_SERVER_SUB_TYPE_OCSP		3 // OCSP-сервер ЦСК

	// Типи сертифікатів відкритих ключів
	 EU_CERT_KEY_TYPE_UNKNOWN		0x00	// Тип відкритого ключа 
									// сертифіката не визначено
	 EU_CERT_KEY_TYPE_DSTU4145		0x01	// Тип відкритого ключа
									// сертифіката ДСТУ-4145
	 EU_CERT_KEY_TYPE_RSA			0x02	// Тип відкритого ключа
									// сертифіката RSA

	// Призначення ключа
	 EU_KEY_USAGE_UNKNOWN			0x0000// Призначення ключа не 
									// визначено
	 EU_KEY_USAGE_DIGITAL_SIGNATURE	0x0001// Ключ ЕЦП
	 EU_KEY_USAGE_KEY_AGREEMENT		0x0010// Ключ протоколу розподілу
									// ключів

	// Типи ключів
	 EU_KEYS_TYPE_NONE				0// Тип ключа не визначено
	 EU_KEYS_TYPE_DSTU_AND_ECDH_WITH_GOSTS	1// Ключ для використання 
									// в алгоритмах ЕЦП ДСТУ-4145 
									// та протоколі розподілу 
									// ключів Діффі-Гелмана в групі 
									// точок ЕК та 
									// ДСТУ ГОСТ 28147:2009
	 EU_KEYS_TYPE_RSA_WITH_SHA			2 // Ключ для використання 
									// в алгоритмі ЕЦП RSA з 
									// функцією гешування SHA

	// Довжини ключів за алгоритмом ЕЦП ДСТУ-4145-2002
	 EU_KEYS_LENGTH_DS_UA_191		1	// Довжина ключа 191 біт 
	 EU_KEYS_LENGTH_DS_UA_257		2	// Довжина ключа 257 біт 
	 EU_KEYS_LENGTH_DS_UA_307		3	// Довжина ключа 307 біт 
	 EU_KEYS_LENGTH_DS_UA_FILE		4	// Довжина ключа обирається з 
									// файлу параметрів
	 EU_KEYS_LENGTH_DS_UA_CERT		5	// Довжина ключа обирається з 
									// сертифікату діючого ос. 
									// ключІ. Підтримується лише 
									// функцією перегенерації ос. 									// ключа

	// Довжини ключів протоколу розподілу ключів за алгоритмом Діффі-Гелмана в 
	// групі точок ЕК
	 EU_KEYS_LENGTH_KEP_UA_257		1	// Довжина ключа 257 біт
	 EU_KEYS_LENGTH_KEP_UA_431		2	// Довжина ключа 431 біт
	 EU_KEYS_LENGTH_KEP_UA_571		3	// Довжина ключа 571 біт
	 EU_KEYS_LENGTH_KEP_UA_FILE		4	// Довжина ключа обирається 
									// з файлу параметрів 
	 EU_KEYS_LENGTH_KEP_UA_CERT		5	// Довжина ключа обирається з 
									// сертифікату діючого ос. 
									// ключІ. Підтримується лише 
									// функцією перегенерації ос. 									// ключа

	// Довжини ключів за алгоритмом ЕЦП RSA
	 EU_KEYS_LENGTH_DS_RSA_1024		1	// Довжина ключа 1024 біта
	 EU_KEYS_LENGTH_DS_RSA_2048		2	// Довжина ключа 2048 біта
	 EU_KEYS_LENGTH_DS_RSA_3072		3	// Довжина ключа 3072 біта
	 EU_KEYS_LENGTH_DS_RSA_4096		4	// Довжина ключа 4096 біта
	 EU_KEYS_LENGTH_DS_RSA_FILE		5	// Довжина ключа обирається
									// з файлу параметрів
	 EU_KEYS_LENGTH_DS_RSA_FILE		6	// Довжина ключа обирається з 
									// сертифікату діючого ос. 
									// ключІ. Підтримується лише 
									// функцією перегенерації ос. 									// ключа

	// Значення алгоритмів захисту даних з використанням алгоритму 
	// направленого шифрування RSA
	 EU_CONTENT_ENC_ALGO_TDES_CBC	4	// Алгоритм TDES-CBC
	 EU_CONTENT_ENC_ALGO_AES_128_CBC	5	// Алгоритм AES-128-CBC
	 EU_CONTENT_ENC_ALGO_AES_192_CBC	6	// Алгоритм AES-192-CBC
	 EU_CONTENT_ENC_ALGO_AES_256_CBC	7	// Алгоритм AES-256-CBC

	// Мови, які підтримуються для локалізованих повідомленнь та помилок 
	// бібліотеки
	 EU_DEFAULT_LANG				0	// Мова за замувчунням
	 EU_UA_LANG				1	// Українська мова
	 EU_RU_LANG				2	// Російська мова
	 EU_EN_LANG				3	// Англійська мова

	// Параметри конфігурації роботи криптографічної бібліотеки
	// Управління функціями, що повертають інформацію про сертифікат
	 EU_RESOLVE_OIDS_PARAMETER		"ResolveOIDs" // Визначає
									// необхідність розшифровувати 
									// OID, за замовчуванням TRUE
	 EU_RESOLVE_OIDS_PARAMETER_LENGTH	4	// Довжина параметру

	// Управління збереженням налаштувань до системного реєстру (або файлу).
	// Не впливає на графічну функцію EUSetSettings. За замовчуванням встановлений 
	// EU_SETTINGS_ID_ALL. Функції EUInitialize, EUFinalize та EUSetSettingsPath 
	// встановлюють його в значення EU_SETTINGS_ID_ALL.
	 EU_SAVE_SETTINGS_PARAMETER		"SaveSettings"
	 EU_SAVE_SETTINGS_PARAMETER_LENGTH	4

	// Управління генерацією особистого ключІ. Якщо TRUE особистий ключ генерується
	// у вигляді PKCS#12 контейнеру
	 EU_MAKE_PKEY_PFX_CONTAINER_PARAMETER	"MakePKeyPFXContainer"
	 EU_MAKE_PKEY_PFX_CONTAINER_LENGTH	4

	// Управління необв`язковими атрибутами ЕЦП
	// Признак необхідності додавання позначки часу від данних. За замовчанням 
	// параметр дорівнює TRUE. Позначка часу буде додаватися лише за умов 
	// використання TSP-сервера в онлайн режимі роботи бібліотеки
	 EU_SIGN_INCLUDE_CONTENT_TIME_STAMP_PARAMETER	"SignIncludeContentTimeStamp"
	 EU_SIGN_INCLUDE_CONTENT_TIME_STAMP_LENGTH	4

	// Тип підпису. За замовчанням параметр дорівнює EU_SIGN_TYPE_CADES_BES
	 EU_SIGN_TYPE_PARAMETER			"SignType"
	 EU_SIGN_TYPE_LENGTH			4

	// Признак необхідності додавати сертифікати ЦСК для підписів з типом - 
	// EU_SIGN_TYPE_CADES_C та EU_SIGN_TYPE_CADES_X_LONG. За замовчанням параметр
	// дорівнює TRUE
	 EU_SIGN_INCLUDE_CA_CERTIFICATES_PARAMETER	"SignIncludeCACertificates"
	 EU_SIGN_INCLUDE_CA_CERTIFICATES_LENGTH		4

	// Тип підпису
	// CAdES-BES - базовий формат підпису. В залежності від параметрів бібліотеки
	// та параметрів виклику фукнції підпису може включати позначку часу від даних 
	// та сертифікат підписувача
	// CAdES-T - підис CAdES-BES, який додатково включає позначку часу від ЕЦП
	// CAdES-C - підпис CAdES-T, який додатково включає посилання на повний набір 
	// сертифікатів для перевірки підпису
	// CAdES-X Long - підпис CAdES-C, який додатково включає повний набір 
	// сертифікатів ЦСК для перевірки підпису, а також відповіді від OCSP сервера 
	// зі статусом сертифіката підписувача
	 EU_SIGN_TYPE_UNKNOWN				0	// Не визначено
	 EU_SIGN_TYPE_CADES_BES				1	// CAdES-BES
	 EU_SIGN_TYPE_CADES_T				4	// CAdES-T
	 EU_SIGN_TYPE_CADES_C				8	// CAdES-C
	 EU_SIGN_TYPE_CADES_X_LONG			16	// CAdES-X Long

	// Визначає інформацію про отримувача, яка включається до зашифрованих даних
	 EU_RECIPIENT_APPEND_TYPE_BY_ISSUER_SERIAL	1	// Інформація про
									// емітента сертифіката та 
									// серійний номер сертифіката
	 EU_RECIPIENT_APPEND_TYPE_BY_KEY_ID		2	// Інформація про
									// ідентифікатор відкритого 
									// ключа

	// Ідентифікатори налаштувань бібліотеки
	 EU_SETTINGS_ID_NONE			0x000	// Жодний
	 EU_SETTINGS_ID_MANDATORY		0x01F	// Обов’язкові
	 EU_SETTINGS_ID_ALL			0x7FF	// Всі
	 EU_SETTINGS_ID_FSTORE			0x001	// Файлове сховище
	 EU_SETTINGS_ID_PROXY			0x002	// Proxy - сервер
	 EU_SETTINGS_ID_TSP			0x004	// TSP - сервер
	 EU_SETTINGS_ID_OCSP			0x008	// OCSP - сервер
	 EU_SETTINGS_ID_LDAP			0x010	// LDAP - сервер
	 EU_SETTINGS_ID_MODE			0x020	// Взаємодії з серверами ЦСК
	 EU_SETTINGS_ID_CMP			0x040	// CMP - сервер
	 EU_SETTINGS_ID_KM			0x080	// Носія особистого ключа
	 EU_SETTINGS_ID_OCSP_ACCESS_INFO_MODE 0x100 // Параметри точок доступу
									// до OCSP - серверів
	 EU_SETTINGS_ID_OCSP_ACCESS_INFO	0x200	// Точки доступу до 
									// OCSP - серверів

	// Максимальний розмір параметру, що може бути збережено до сховища
	 EU_STORAGE_VALUE_MAX_LENGTH		0x7FFF

	// Інформація про доступність серверу OCSP
	 EU_OCSP_SERVER_STATE_UNKNOWN	0	// Не визначено
	 EU_OCSP_SERVER_STATE_AVAILABLE	1	// Доступний
	 EU_OCSP_SERVER_STATE_UNAVAILABLE	2	// Не доступний

	// Параметри конфігурації контекста криптографічної бібліотеки
	// Управління функціями, що перевіряють строк чинності сертифіката особистого
	// ключа, для контексту. Можливі значення TRUE = 1, або FALSE = 0
	 EU_CHECK_PRIVATE_KEY_CONTEXT_PARAMETER		"CheckPrivateKey"
	 EU_CHECK_PRIVATE_KEY_CONTEXT_PARAMETER_LENGTH	4

	// Управління функціями, що повертають інформацію про сертифікат
	 EU_RESOLVE_OIDS_CONTEXT_PARAMETER		"ResolveOIDs" // Визначає
									// необхідність розшифровувати 
									// OID, за замовчуванням TRUE
	 EU_RESOLVE_OIDS_ CONTEXT_PARAMETER_LENGTH	4// Довжина параметру
	// Управління функціями, що експортують особистий ключ. Можливі значення
	// TRUE = 1, або FALSE = 0
	 EU_EXPORATABLE_CONTEXT_CONTEXT_PARAMETER	"ExportableContext" // 
									// Визначає призначення
									// контексту для експорту 
									// ключів
	 EU_EXPORATABLE_CONTEXT_CONTEXT_PARAMETER_LENGTH	4// Довжина
									// параметру

	// Тип інформації про отримувача, що міститься в зашифрованих даних
	 EU_RECIPIENT_INFO_TYPE_ISSUER_SERIAL	1 // Реквізити ЦСК, що видав 
									// сертифікат та реєстраційний 
									// номер сертифіката
	 EU_RECIPIENT_INFO_TYPE_KEY_ID		2 // Ідентифікатор відкритого 
									// ключа отримувача

	// Типи алгоритмів гешування
	 EU_CTX_HASH_ALGO_UNKNOWN			0 // Не визначено
	 EU_CTX_HASH_ALGO_GOST34311			1 // ГОСТ 34.311-95
	 EU_CTX_HASH_ALGO_SHA160			2 // SHA-1
	 EU_CTX_HASH_ALGO_SHA224			3 // SHA-224
	 EU_CTX_HASH_ALGO_SHA256			4 // SHA-256

	// Типи алгоритмів підпису
	 EU_CTX_SIGN_UNKNOWN				0 // Не визначено
	 EU_CTX_SIGN_DSTU4145_WITH_GOST34311	1 // ЕЦП за ДСТУ 4145-2002 та
									// геш ГОСТ 34.311-95
	 EU_CTX_SIGN_RSA_WITH_SHA			2 // ЕЦП за RSA та геш SHA

	// Типи розділів реєстру
	 EU_REG_KEY_ROOT_PATH_DEFAULT		0 // За замовчанням
	 EU_REG_KEY_ROOT_PATH_HKLM			1 // Поточного комп’ютера
	 EU_REG_KEY_ROOT_PATH_HKCU			2 // Поточного користувача
	 EU_REG_KEY_ROOT_PATH_CURRENT		3 // Поточні

	// Граничні значення тегів для запису даних на пристрій
	 EU_DEV_CTX_MIN_PUBLIC_DATA_ID		0x10 // Мінімальне значення 
									// тега відкритих данних
	 EU_DEV_CTX_MAX_PUBLIC_DATA_ID		0x4F // Максимальне значення 
									// тега відкритих данних
	 EU_DEV_CTX_MIN_CONST_PUBLIC_DATA_ID	0x50 // Мінімальне значення 
									// тега незмінних відкритих 
									// данних
	 EU_DEV_CTX_MAX_CONST_PUBLIC_DATA_ID	0x6F // Максимальне значення 
									// тега незмінних відкритих 
									// данних
	 EU_DEV_CTX_MIN_CONST_PRIVATE_DATA_ID	0x70 // Мінімальне значення 
									// тега незмінних особистих 
									// данних
	 EU_DEV_CTX_MAX_CONST_PRIVATE_DATA_ID
								0x8F // Максимальне значення 
									// тега незмінних особистих 
									// данних
	 EU_DEV_CTX_MIN_PRIVATE_DATA_ID	0x90 // Мінімальне значення 
									// тега особистих данних
	 EU_DEV_CTX_MAX_PRIVATE_DATA_ID	0xAF // Максимальне значення 
									// тега особистих данних

	// Значення спеціальних тегів пристрою
	 EU_DEV_CTX_DATA_ID_SERIAL_NUMBER	0xD1 // Тег серійного номеру 
									// пристрою
	 EU_DEV_CTX_DATA_ID_SYSTEM_KEY_VERSION
								0xD4 // Тег версії відкритого
									// ключа серверу
	 EU_DEV_CTX_DATA_ID_UPDATE_COUNTER	0xD6 // Тег лічильника 
									// оновлення

	// Індекси параметрів данних версії відкритого ключа сервера, що отримуються з 
	// пристрою
	 EU_DEV_CTX_SYSTEM_KEY_TYPE_INDEX	0 // Індекс типу відкритого ключа
	 EU_DEV_CTX_SYSTEM_KEY_VERSION_INDEX
								1 // Індекс версії відкритого ключа

	// Символьний ідентифікатор, привласнений АЦСК, з шлюзом якого буде працювати 
	// бібліотекаю. Фіксоване значення
	 EU_HEADER_CA_TYPE			"UA1"

	// Максимальний розмір символьного ідентифікатора, привласненого АЦСК, з шлюзом 
	// якого буде працювати бібліотекаю
	 EU_HEADER_MAX_CA_TYPE_SIZE		3

	// Тип криптографічного заголовку
	 EU_HEADER_PART_TYPE_SIGNED		1 // Підписані дані
	 EU_HEADER_PART_TYPE_ENCRYPTED	2 // Зашифровані дані
	 EU_HEADER_PART_TYPE_STAMPED		3 // Печатка
	 EU_HEADER_PART_TYPE_CERTCRYPT	4 // Сертифікат відправника

	// Типи запитів на зміну статусу сертифіката
	 EU_CCS_TYPE_REVOKE				1 // Скасування сертифіката
	 EU_CCS_TYPE_HOLD				2 // Блокування сертифіката

	 EU_REVOCATION_REASON_UNKNOWN		0 // Невідома
	 EU_REVOCATION_REASON_KEY_COMPROMISE	1 // Компрометація ос. ключа
	 EU_REVOCATION_REASON_NEW_ISSUED		2 // Генерація нового ос. ключа

І.4 Типи даних
Звичайні типи даних незмінні для Python 2.7 та Python 3. Тип строк розрізняється. В приведеному описі інтерфейсу:
–	тип bytes визначає байтову строку (тип str для Python 2.7 чи bytes для Python 3);
–	тип unicode визначає Юнікод кодовану строку (тип unicode для Python 2.7 чи str для Python 3);
–	 тип str визначає, що може використовуватися як bytes так і unicode.
Власні структури бібліотеки підпису мають тип dict. Коли така структура виступає в якості вихідного параметра, то в функцію передається пустий dict в який виконується запис.
Признак заповнення структури bFilled використовується виключно внутрішньоми функціями бібліотеки та аналізуватися не повинен.
Поле dwVersion відповідає за версію структури та його зміна вказує на зміни полей структури.
Нижче наведений опис структур з ключами та типами полів
І.4.1 EU_KEY_MEDIA
	// Структура з параметрами носія особистого ключа
	dict = 
	{
		"dwTypeIndex":		long,		// Індекс типу носія особистого ключа
		"dwDevIndex":		long,		// Індекс пристрою носія особистого 
								// ключа
		"szPassword":		unicode	//Пароль доступу до носія 
								// особистого ключа
	}

І.4.2 EU_CERT_OWNER_INFO
	// Структура із описом інформації про сертифікат власника особистого ключа
	dict =
	{
		"bFilled":		Boolean,		// Признак заповнення структури

		"pszIssuer":	unicode,		// Ім’я ЦСК, що видав сертифікат
		"pszIssuerCN":	unicode,		// Реквізити ЦСК, що видав сертифікат
		"pszSerial":	unicode,		// Реєстраційний номер сертифіката

		"pszSubject":	unicode,		// Ім’я власника сертифіката
		"pszSubjCN":	unicode,		// Реквізити власника сертифіката
		"pszSubjOrg":	unicode,		// Організація до якої належить 
								// власник сертифіката
		"pszSubjOrgUnit":	unicode,		// Підрозділ організації до якої 
								// належить власник сертифіката
		"pszSubjTitle":	unicode,		// Посада власника сертифіката
		"pszSubjState":	unicode,		// Назва області до якої належить 
								// власник сертифіката
		"pszSubjLocality":	unicode,	// Назва населеного пункту до якого 
								// належить власник сертифіката
		"pszSubjFullName":	unicode,	// Повне ім’я власника сертифіката
		"pszSubjAddress":	unicode,		// Адреса власника сертифіката
		"pszSubjPhone":	unicode,		// Номер телефону власника 
								// сертифіката
		"pszSubjEMail":	unicode,		//Адреса електронної пошти власника 
								// сертифіката
		"pszSubjDNS":	unicode,		// DNS-ім`я чи інше технічного засобу
		"pszSubjEDRPOUCode":	unicode,	// Код ЄДРПОУ власника сертифіката
		"pszSubjDRFOCode":	unicode,	// Код ДРФО власника сертифіката
	}

І.4.3 EU_CERT_INFO
	// Структура із описом детальної інформації про сертифікат
	dict =
	{
		"bFilled":		Boolean,		// Признак заповнення структури

		"dwVersion":	long,			// Версія структури з сертифікатом

		"pszIssuer":	unicode,		// Ім’я ЦСК, що видав сертифікат
		"pszIssuerCN":	unicode,		// Реквізити ЦСК, що видав сертифікат
		"pszSerial":	unicode,		// Реєстраційний номер сертифіката

		"pszSubject":	unicode,		// Ім’я власника сертифіката
		"pszSubjCN":	unicode,		// Реквізити власника сертифіката
		"pszSubjOrg":	unicode,		// Організація до якої належить 
								// власник сертифіката
		"pszSubjOrgUnit":	unicode,		// Підрозділ організації до якої 
								// належить власник сертифіката
		"pszSubjTitle":	unicode,		// Посада власника сертифіката
		"pszSubjState":	unicode,		// Назва області до якої належить 
								// власник сертифіката
		"pszSubjLocality":	unicode,	// Назва населеного пункту до якого 
								// належить власник сертифіката
		"pszSubjFullName":	unicode,	// Повне ім’я власника сертифіката
		"pszSubjAddress":	unicode,		// Адреса власника сертифіката
		"pszSubjPhone":	unicode,		// Номер телефону власника 
								// сертифіката
		"pszSubjEMail":	unicode,		// Адреса електронної пошти власника 
								// сертифіката
		"pszSubjDNS":	unicode,		// DNS-ім`я чи інше технічного засобу
		"pszSubjEDRPOUCode":	unicode,	// Код ЄДРПОУ власника сертифіката
		"pszSubjDRFOCode":	unicode,	// Код ДРФО власника сертифіката

		"pszSubjNBUCode":	unicode,		// Ідентифікатор НБУ власника 
								// сертифіката
		"pszSubjSPFMCode":	unicode,	// Код СПФМ власника сертифіката 

		"pszSubjOCode":	unicode,		// Код організації власника 
								// сертифіката
		"pszSubjOUCode":	unicode,		// Код підрозділу власника 
								// сертифіката
		"pszSubjUserCode":	unicode,	// Код користувача власника 
								// сертифіката
		"stCertBeginTime":	SYSTEMTIME,	// Час введення сертифіката в дію
		"stCertEndTime":	SYSTEMTIME,		// Дата закінчення дії сертифіката
		"bPrivKeyTimes":		Boolean,	// Признак наявності строку дії 
								// особистого ключа
		"stPrivKeyBeginTime":	SYSTEMTIME,	// Час введення в дію особистого
								// ключа
		"stPrivKeyEndTime":	SYSTEMTIME,	// Час виведення з дії особистого 
								// ключа

		"dwPublicKeyBits":	long,		// Довжина відкритого ключа в бітах
		"pszPublicKey":		unicode,	// Відкритий ключ у вигляді строки
		"pszPublicKeyID":		unicode,	// Ідентифікатор відкритого ключа у 
								// вигляді строки
		"bECDHPublicKey":		Boolean,	// Признак наявності відкритого ключа 
								// протоколу розподілу ключів
		"dwECDHPublicKeyBits":	long,		// Довжина відкритого ключа протоколу 
								// розподілу ключів в бітах
		"pszECDHPublicKey":	unicode,	// Відкритий ключ протоколу розподілу
								// ключів у вигляді строки
		"pszECDHPublicKeyID":	unicode,	// Ідентифікатор відкритого ключа 
								// протоколу розподілу ключів у
								// вигляді строки
		"pszIssuerPublicKeyID":	unicode	// Ідентифікатор відкритого ключа 
								// ЦСК у вигляді строки

		"pszKeyUsage":	unicode,		// Використання ключів
		"pszExtKeyUsages":	unicode,	// Уточнене призначення ключів
		"pszPolicies":	unicode,		// Правила сертифікації

		"pszCRLDistribPoint1":	unicode,	// Точка доступу до повних СВС
		"pszCRLDistribPoint2":	unicode,	// Точка доступу до часткових СВС

		"bPowerCert":	Boolean,		// Признак того, що сертифікат 
								// посилений

		"bSubjType":	Boolean,		// Тип власника сертифікату
		"bSubjCA":		Boolean		// Признак того, що власник 
								// сертифікату ЦСК
	}

І.4.4 EU_CERT_INFO_EX
	// Структура із описом детальної інформації про сертифікат(розширена)
	dict =
	{
		"bFilled":		Boolean,		// Признак заповнення структури

		"dwVersion":	long,			// Версія структури з сертифікатом

		"pszIssuer":	unicode,		// Ім’я ЦСК, що видав сертифікат
		"pszIssuerCN":	unicode,		// Реквізити ЦСК, що видав сертифікат
		"pszSerial":	unicode,		// Реєстраційний номер сертифіката

		"pszSubject":	unicode,		// Ім’я власника сертифіката
		"pszSubjCN":	unicode,		// Реквізити власника сертифіката
		"pszSubjOrg":	unicode,		// Організація до якої належить 
								// власник сертифіката
		"pszSubjOrgUnit":	unicode,		// Підрозділ організації до якої 
								// належить власник сертифіката
		"pszSubjTitle":	unicode,		// Посада власника сертифіката
		"pszSubjState":	unicode,		// Назва області до якої належить 
								// власник сертифіката
		"pszSubjLocality":	unicode,	// Назва населеного пункту до якого 
								// належить власник сертифіката
		"pszSubjFullName":	unicode,	// Повне ім’я власника сертифіката
		"pszSubjAddress":		unicode,	// Адреса власника сертифіката
		"pszSubjPhone":		unicode,	// Номер телефону власника 
								// сертифіката
		"pszSubjEMail":	unicode,		//Адреса електронної пошти власника 
								// сертифіката
		"pszSubjDNS":	unicode,		// DNS-ім`я чи інше технічного засобу
		"pszSubjEDRPOUCode":	unicode,	// Код ЄДРПОУ власника сертифіката
		"pszSubjDRFOCode":	unicode,	// Код ДРФО власника сертифіката

		"pszSubjNBUCode":	unicode,		// Ідентифікатор НБУ власника 
								// сертифіката
		"pszSubjSPFMCode":	unicode,	// Код СПФМ власника сертифіката 

		"pszSubjOCode":		unicode,	// Код організації власника 
								// сертифіката
		"pszSubjOUCode":		unicode,	// Код підрозділу власника 
								// сертифіката
		"pszSubjUserCode":	unicode,	// Код користувача власника 
								// сертифіката
		"stCertBeginTime":	SYSTEMTIME,	// Час введення сертифіката в дію
		"stCertEndTime":		SYSTEMTIME,	// Дата закінчення дії сертифіката
		"bPrivKeyTimes":		Boolean,	// Признак наявності строку дії 
								// особистого ключа
		"stPrivKeyBeginTime":	SYSTEMTIME,	// Час введення в дію особистого
								// ключа
		"stPrivKeyEndTime":	SYSTEMTIME,	// Час виведення з дії особистого 
								// ключа

		"dwPublicKeyBits":	long,		// Довжина відкритого ключа в бітах
		"pszPublicKey":		unicode,	// Відкритий ключ у вигляді строки
		"pszPublicKeyID":		unicode, 	// Ідентифікатор відкритого ключа у 
								// вигляді строки

		"pszIssuerPublicKeyID":	unicode,	// Ідентифікатор відкритого ключа 
								// ЦСК у вигляді строки

		"pszKeyUsage":		unicode,	// Використання ключів у вигляді 
								// строки
		"pszExtKeyUsages":	unicode,	// Уточнене призначення ключів
		"pszPolicies":		unicode,	// Правила сертифікації

		"pszCRLDistribPoint1":	unicode,	// Точка доступу до повних СВС
		"pszCRLDistribPoint2":	unicode,	// Точка доступу до часткових СВС

		"bPowerCert":		Boolean,	// Признак того, що сертифікат 
								// посилений

		"bSubjType":		Boolean,	// Тип власника сертифікату
		"bSubjCA":			Boolean,	// Признак того, що власник 
								// сертифікату ЦСК

		"iChainLength":		INT,		// Обмеження на довжину ланцюжка 
								// сертифікатів

		"pszUPN":			unicode,	// UPN-ім`я власника сертифіката

		"dwPublicKeyType":	long,		// Тип відкритого ключа
		"dwKeyUsage":		long,		// Використання ключів

		"pszRSAModul":		unicode,	// Модуль RSA у вигляді строки
		"pszRSAExponent":		unicode,	// Експонента RSA у вигляді строки

		"pszOCSPAccessInfo":	unicode,	// Точка доступу до OCSP-сервера
		"pszIssuerAccessInfo":	unicode,	// Точка доступу до сертифікатів
		"pszTSPAccessInfo":	unicode,	// Точка доступу до TSP-сервера

		"bLimitValueAvailable":	Boolean,	// Признак наявності обмеження на 
								// транзакцію
		"dwLimitValue":		long,		// Максимальне обмеження на 
								// транзакцію
		"pszLimitValueCurrency":unicode,	// Валюта максимального обмеження на 
								// транзакцію
		"dwSubjType":		long,			// Тип власника сертифіката
								// (поле доступне з dwVersion > 2)
		"dwSubjSubType":		long,		// Тип власника сертифіката для
								// серверів ЦСК
								// (поле доступне з dwVersion > 2)

		"pszSubjUNZR":	unicode,		// Номер УНЗР власника сертифіката
								// (поле доступне з dwVersion > 3)

		"pszSubjCountry":	unicode		// Код країни власника сертифіката
								// (поле доступне з dwVersion > 4)
	} 

І.4.5 EU_CERTIFICATES
	// Список з інформацією про сертифікати 
	list[EU_CERT_INFO_EX]

І.4.6 EU_CRL_INFO
	// Структура із описом інформації про список відкликаних сертифікатів (СВС)
	dict =
	{
		"bFilled":		Boolean,		// Признак заповнення структури

		"pszIssuer":	unicode,		// Ім’я ЦСК, що випустив СВС
		"pszIssuerCN":	unicode,		// Реквізити ЦСК, що випустив СВС

		"dwCRLNumber":	long,			// Серійний номер
		"stThisUpdate":	SYSTEMTIME,		// Час формування СВС
		"stNextUpdate":	SYSTEMTIME		// Час наступного формування
	}

І.4.7 EU_CRL_DETAILED_INFO
	// Структура із описом детальної інформації про СВС
	dict =
	{
		"bFilled":		Boolean,		// Признак заповнення структури

		"dwVersion":	long,			// Версія структури з СВС

		"pszIssuer":	unicode,		// Ім’я ЦСК, що випустив СВС
		"pszIssuerCN":	unicode,		// Реквізити ЦСК, що випустив СВС
		"pszIssuerPublicKeyID":	unicode,	// Ідентифікатор відкритого ключа ЕЦП 
								// ЦСК

		"dwCRLNumber":	long,			// Серійний номер
		"stThisUpdate":	SYSTEMTIME,		// Час формування СВС
		"stNextUpdate":	SYSTEMTIME,		// Час наступного формування

		"dwRevokedItemsCount":	long		// Кількість відкликаних сертифікатів
	}

І.4.8 EU_SIGN_INFO, EU_ENVELOP_INFO
	// Структура із описом інформації про підпис (сертифікат підписувача 
	// та час підпису) або про відправника зашифрованих даних (сертифікат 
	// відправника та час підпису, якщо міститься підпис)
	dict =
	{
		"bFilled":		Boolean,		// Признак заповнення структури

		"pszIssuer":	unicode,		// Ім’я ЦСК, що видав сертифікат
		"pszIssuerCN":	unicode,		// Реквізити ЦСК, що видав сертифікат
		"pszSerial":	unicode,		// Реєстраційний номер сертифіката

		"pszSubject":	unicode,		// Ім’я власника сертифіката
		"pszSubjCN":	unicode,		// Реквізити власника сертифіката
		"pszSubjOrg":	unicode,		// Організація до якої належить 
								// власник сертифіката
		"pszSubjOrgUnit":	unicode,		// Підрозділ організації до якої 
								// належить власник сертифіката
		"pszSubjTitle":	unicode,		// Посада власника сертифіката
		"pszSubjState":	unicode,		// Назва області до якої належить 
								// власник сертифіката
		"pszSubjLocality":	unicode,	// Назва населеного пункту до якого 
								// належить власник сертифіката
		"pszSubjFullName":	unicode,	// Повне ім’я власника сертифіката
		"pszSubjAddress":		unicode,	// Адреса власника сертифіката
		"pszSubjPhone":		unicode,	// Номер телефону власника 
								// сертифіката
		"pszSubjEMail":		unicode,	// Адреса електронної пошти власника 
								// сертифіката
		"pszSubjDNS":		unicode,	// DNS-ім`я чи інше технічного засобу
		"pszSubjEDRPOUCode":	unicode,	// Код ЄДРПОУ власника сертифіката
		"pszSubjDRFOCode":	unicode,	// Код ДРФО власника сертифіката

		"bTimeAvail":		Boolean,	// Признак наявності часу підпису
		"bTimeStamp":		Boolean,	// Признак наявності позначки часу
								// отриманої з TSP сервера
		"Time":		SYSTEMTIME		// Час підпису або позначка часу
	}

І.4.9 EU_CR_INFO
	// Структура із описом інформації про запит на формування сертифікату
	dict =
	{
		"bFilled":		Boolean,		// Признак заповнення структури

		"dwVersion":	long,			// Версія структури з запитом на 
								// сертифікацію

		"bSimple":		Boolean,		// Признак простого запиту на 
								// формування сертифікату

		"pszSubject":	unicode,		// Ім’я власника сертифіката
		"pszSubjCN":	unicode,		// Реквізити власника сертифіката
		"pszSubjOrg":	unicode,		// Організація до якої належить 
								// власник сертифіката
		"pszSubjOrgUnit":	unicode,		// Підрозділ організації до якої 
								// належить власник сертифіката
		"pszSubjTitle":	unicode,		// Посада власника сертифіката
		"pszSubjState":	unicode,		// Назва області до якої належить 
								// власник сертифіката
		"pszSubjLocality":	unicode,	// Назва населеного пункту до якого 
								// належить власник сертифіката
		"pszSubjFullName":	unicode,	// Повне ім’я власника сертифіката
		"pszSubjAddress":		unicode,	// Адреса власника сертифіката
		"pszSubjPhone":		unicode,	// Номер телефону власника 
								// сертифіката
		"pszSubjEMail":		unicode,	// Адреса електронної пошти власника 
								// сертифіката
		"pszSubjDNS":		unicode,	// DNS-ім`я чи інше технічного засобу
		"pszSubjEDRPOUCode":	unicode,	// Код ЄДРПОУ власника сертифіката
		"pszSubjDRFOCode":	unicode,	// Код ДРФО власника сертифіката

		"pszSubjNBUCode":		unicode,	// Ідентифікатор НБУ власника 
								// сертифіката
		"pszSubjSPFMCode":	unicode,	// Код СПФМ власника сертифіката 

		"pszSubjOCode":		unicode,	// Код організації власника 
								// сертифіката
		"pszSubjOUCode":		unicode,	// Код підрозділу власника 
								// сертифіката
		"pszSubjUserCode":	unicode,	// Код користувача власника 
								// сертифіката

		"bCertTimes":		Boolean,	// Признак наявності строку дії 
								// сертифікату
		"stCertBeginTime":	SYSTEMTIME,	// Час введення сертифіката в дію
		"stCertEndTime":		SYSTEMTIME,	// Дата закінчення дії сертифіката
		"bPrivKeyTimes":		Boolean,	// Признак наявності строку дії 
								// особистого ключа
		"stPrivKeyBeginTime":	SYSTEMTIME,	// Час введення в дію особистого
								// ключа
		"stPrivKeyEndTime":	SYSTEMTIME,	// Час виведення з дії особистого 
								// ключа

		"dwPublicKeyType":	long,		// Тип відкритого ключа

		"dwPublicKeyBits":	long,		// Довжина відкритого ключа в бітах
		"pszPublicKey":		unicode,	// Відкритий ключ у вигляді строки
		"pszRSAModul":		unicode,	// Модуль RSA у вигляді строки
		"pszRSAExponent":		unicode,	// Експонента RSA у вигляді строки

		"pszPublicKeyID":		unicode,	// Ідентифікатор відкритого ключа у 
								// вигляді строки

		"pszExtKeyUsages":	unicode,	// Уточнене призначення ключів

		"pszCRLDistribPoint1":	unicode,	// Точка доступу до повних СВС
		"pszCRLDistribPoint2":	unicode,	// Точка доступу до часткових СВС

		"bSubjType":		Boolean,	// Признак наявності типу власника 
								// ключа
		"dwSubjType":		long,		// Тип власника ключа
		"dwSubjSubType":		long,		// Підтип власника ключа

		"bSelfSigned":		Boolean,	// Признак самопідписаного 
								// запиту на сертифікат
		"pszSignIssuer":		unicode,	// Реквізити ЦСК заявника
		"pszSignSerial":		unicode,	// РН сертифіката заявника

		"pszSubjUNZR":		unicode,	// Номер УНЗР власника сертифіката
								// (поле доступне з dwVersion > 1)

		"pszSubjCountry":		unicode,	// Код країни власника сертифіката
								// (поле доступне з dwVersion > 2)
	}

І.4.10 EU_USER_INFO
	// Інформація про користувача
	dict =
	{
		"dwVersion":	long,			// Версія структури з запитом на 
								// сертифікацію
		"szCommonName":	unicode,		// Повне найменування організації 
								// користувача
		"szLocality":	unicode,		// Назва населеного 
								// пункту де мешкає користувач
		"szState":		unicode,		// Назва області де мешкає 
								// користувач
		"szOrganiztion":	unicode,		// Назва організації користувача
		"szOrgUnit":	unicode,		// Назва підрозділу
								// організації користувача
		"szTitle":		unicode,		// Посада користувача
		"szStreet":		unicode,		// Назва вулиці де мешкає 
								// користувач
		"szPhone":		unicode,		// Номер телефону користувача
		"szSurname":	unicode,		// Прізвище користувача
		"szGivenname":	unicode,		// Ім'я по-батькові
								// користувача
		"szEMail":		unicode,		// Поштова адреса користувача
		"szDNS":		unicode,		// Адреса користувача
		"szEDRPOUCode":	unicode,		// Код ЄДРПОУ користувача
		"szDRFOCode":	unicode,		// Код ДРФО користувача
		"szNBUCode":	unicode,		// Код НБУ користувача
		"szSPFMCode":	unicode,		// Код СПФМ користувача
		"szOCode":		unicode,		// Код організації користувача
		"szOUCode":		unicode,		// Код підрозділу 
								// організації користувача
		"szUserCode":	unicode,		// Код користувача
		"szUPN":		unicode,		// UPN-ім'я користувача

		"szUNZR":		unicode,		// Номер УНЗР
								// (поле доступне з dwVersion > 2)

		"szCountry":	unicode,		// Код країни
								// (поле доступне з dwVersion > 3)
	} 

І.4.11 EU_SCC_STATISTIC
	// Структура із статистикою роботи функцій клієнта захиста
	dict =
	{
		"dwVersion":		long,		// Версія структури з статистикою

		"dwlActiveSessions":	long long,	// Кількість активних сесій
		"dwlGatedSessions":	long long,	// Кількість оброблених сесій
		"dwlUnprotectedData":	long long,	// Кількість відкритих даних в байтах
		"dwlProtectedData":	long long,	// Кількість захищених даних в байтах
	} EU_SCC_STATISTIC, *PEU_SCC_STATISTIC;

І.4.12 EU_TIME_INFO
	// Інформація про час
	dict =
	{
		"dwVersion":	long,			// Версія структури з інформацією про
								// час
		"bTimeAvail":	Boolean,		// Признак наявності часу
		"bTimeStamp":	Boolean,		// Признак наявності позначки часу
								// отриманої з TSP сервера
		"Time":		SYSTEMTIME		// Час або позначка часу
	}

І.4.13 SYSTEMTIME
	// Інформація про час
	dict =
	{
		"wYear":		long,			// Рік
		"wMonth":		long,			// Місяць
		"wDayOfWeek":	long,			// День тижня
		"wDay":		long,			// Число місяця
		"wHour":		long,			// Години
		"wMinute": 		long,			// Хвилини
		"wSecond": 		long,			// Секунди
		"wMilliseconds":	long			// Мілісекунди
	}

І.4.14 EU_FILE_STORE_SETTINGS
	// Параметри файлового сховища
	dict =
	{
		"szPath":			unicode,	// Каталог, в якому 
								// розміщуються сертифікати та СВС
		"bCheckCRLs":		Boolean,	// Признак необхідності 
								// використання СВС при визначенні 
								// статусу сертифіката
		"bAutoRefresh":		Boolean,	// Признак необхідності 
								// автоматичного виявлення змін у 
								// файловому сховищі при записі, 
								// модифікації чи видаленні 
								// сертифікатів та СВС
		"bOwnCRLsOnly":		Boolean,	// Признак необхідності 
								// використання СВС тільки власного 
								// ЦСК користувача
		"bFullAndDeltaCRLs":	Boolean,	// Признак 
								// необхідності перевірки наявності 
								// двох діючих СВС – повного та 
								// часткового
		"bAutoDownloadCRLs":	Boolean,	// Признак 
								// необхідності автоматичного 
								// завантаження СВС
		"bSaveLoadedCerts":	Boolean,	// Признак 
								// необхідності автоматичного 
								// збереження сертифікатів отриманих 
								// з LDAP-сервера чи за протоколом 
								// OCSP у файлове сховище
		"dwExpireTime":		long		// Час зберігання стану
								// перевіреного сертифіката 
								// (у секундах)

	}

І.4.15 EU_PROXY_SETTINGS
	// Параметри Proxy-сервера
	dict =
	{
		"bUseProxy":		Boolean,	// Признак необхідності 
								// підключення до ЦСК через
								// proxy-сервер
		"bAnonymous":		Boolean,	// Признак анонімного 
								// proxy-сервера
		"szAddress":		unicode,	// ІР-адреса або DNS-ім’я 
								// proxy-сервера
		"szPort":			unicode,	// TCP-порт proxy-сервера
		"szUser":			unicode,	// Ім’я користувача 
								// proxy-сервера
		"szPassword":		unicode,	// Пароль доступу 
								// користувача до proxy-сервера
		"bSavePassword":		Boolean	// Признак зберігання 
								// пароля доступу до proxy-сервера

	}

І.4.16 EU_OCSP_SETTINGS
	// Параметри OCSP-сервера
	dict =
	{
		"bUseOCSP":			Boolean,	// Признак необхідності 
								// використання механізму визначення 
								// статусу сертифікатів за допомогою 
								// протоколу OCSP
		"bBeforeStore":		Boolean,	// Признак черговості 
								// перевірки статусу сертифіката
		"szAddress":		unicode,	// ІР-адреса або DNS-ім’я 
								// OCSP-сервера
		"szPort":			unicode	// TCP-порт OCSP-сервера


	}

І.4.17 EU_MODE_SETTINGS
	// Параметри взаємодії з серверами ЦСК
	dict =
	{
		"bOfflineMode":		Boolean	// Off-line режим роботи 
								// з серверами ЦСК. Якщо TRUE - 
								// взаємодія з серверами ЦСК не
								// відбувається

	}

І.4.18 EU_TSP_SETTINGS
	// Параметри TSP-сервера
	dict =
	{
		"bGetStamps":		Boolean,	// Признак необхідності 
								// отримувати позначки часу під час 
								// формування підпису
		"szAddress":		unicode,	// ІР-адреса або DNS-ім’я 
								// TSP-сервера
		"szPort":			unicode 	// TCP-порт TSP-сервера

	}

І.4.19 EU_LDAP_SETTINGS
	// Параметри LDAP-сервера
	dict =
	{
		"bUseLDAP":			Boolean,	// Признак необхідності 
								// використання LDAP-сервера
		"szAddress":		unicode,	// ІР-адреса або DNS-ім’я 
								// LDAP-сервера
		"szPort":			unicode,	// TCP-порт LDAP-сервера
		"bAnonymous":		Boolean,	// Признак анонімного 
								// доступу до LDAP-сервера
		"szUser":			unicode,	// Ім’я користувача
		"szPassword":		unicode	// Пароль доступу 
								// користувача до LDAP-сервера

	}

І.4.20 EU_CMP_SETTINGS
	// Параметри CMP-сервера
	dict =
	{
		"bUseCMP":			Boolean,	// Признак необхідності 
								// використання CMP-сервера
		"szAddress":		unicode,	// ІР-адреса або DNS-ім’я 
								// CMP-сервера
		"szPort":			unicode,	// TCP-порт CMP-сервера
		"szCommonName":		unicode	// Реквізит
								// сертифіката "повне найменування 
								// організації" ("commonName")

	}

І.4.21 EU_OCSP_ACCESS_INFO_MODE_SETTINGS
	// Параметри використання точок доступу до серверів OCSP
	dict =
	{
		"bEnabled":			Boolean	// Вхідний. Признак використання 
								// точок доступу до серверів OCSP

	}

І.4.22 EU_OCSP_ACCESS_INFO _SETTINGS
	// Параметри доступу до серверу OCSP за реквізитами ЦСК
	dict =
	{
		"szIssuerCN":		unicode,	// Вхідний. Реквізити ЦСК
		"szAddress":		unicode,	// Вхідний. Точка доступу до
								// OCSP - серверу
		"szPort":			unicode	// Вхідний. TCP-порт OCSP - серверу

	}

І.5 Функції бібліотеки
Опис прототипів функцій та параметри (Name: Type) їх виклику наведений нижче.
І.5.1 Функції загального призначення
	EUInitialize
	// Ініціалізація бібліотеки.
	def Initialize ()

	EUFinalize
	// Завершення роботи з бібліотекою
	def Finalize ()

	EUIsInitialized
	// Перевірка стану бібліотеки
	def IsInitialized () -> Boolean

	EUSetUIMode
	// Встановлення режиму використання графічного інтерфейсу у разі виникнення 
	// помилок. Якщо викливається до функції ініціалізації бібліотеки Initialize, 
	// бібліотеку буде завантажено без графічного модуля
	def SetUIMode(
		bUIMode:		Boolean)		// Вхідний. Режим використання
								// графічного інтерфейсу у разі
								// виникнення помилок


	EUGeneratePRNGSequence
	// Генерація псевдовипадкової послідовності за допомогою ГПВЧ згідно
	// дод. А ДСТУ 4145-2002
	def GeneratePRNGSequence(
		pbData:		list[bytes],	// Вихідний. Буфер для 
								// запису послідовності
		dwDataLength:	long)			// Вхідний. Розмір послідовності

	EUDoesNeedSetSettings
	// Отримання признаку необхідності встановлення параметрів
	def DoesNeedSetSettings () -> Boolean

	EUGetModeSettings, EUSetModeSettings
	// Отримання параметрів взаємодії з серверами ЦСК
	def GetModeSettings (
		pbOfflineMode:	EU_MODE_SETTINGS); // Вихідний. Параметри взаємодії 
								// з серверами ЦСК

	// Встановлення параметрів взаємодії з серверами ЦСК
	def SetModeSettings (
		bOfflineMode:	EU_MODE_SETTINGS); // Вхідний. Параметри взаємодії 
								// з серверами ЦСК. Усі поля повинні 
								//бути заповнені

	EUGetFileStoreSettings, EUSetFileStoreSettings,
	// Отримання параметрів файлового сховища (див. табл. 3.1)
	def GetFileStoreSettings (
		pszPath:	EU_FILE_STORE_SETTINGS)	// Вихідний. Параметри файлового
								// сховища

	// Встановлення параметрів файлового сховища (див. табл. 3.1)
	def SetFileStoreSettings (
		pszPath:	EU_FILE_STORE_SETTINGS)	// Вхідний. Параметри файлового
								// сховища. Усі поля повинні бути 
								// заповнені

	EUGetProxySettings, EUSetProxySettings
	// Отримання параметрів Proxy-сервера (див. табл. 3.1)
	def GetProxySettings (
		pbUseProxy:	EU_PROXY_SETTINGS)	// Вихідний. Параметри Proxy-сервера

	// Встановлення параметрів Proxy-сервера (див. табл. 3.1)
	def SetProxySettings (
		bUseProxy:	EU_PROXY_SETTINGS)	// Вхідний. Параметри Proxy-сервера.
								// Усі поля повинні бути 
								// заповнені

	EUGetOCSPSettings, EUSetOCSPSettings
	// Отримання параметрів OCSP-сервера (див. табл. 3.1)
	def GetOCSPSettings (
		pbUseOCSP:	EU_OCSP_SETTINGS)	// Вихідний. Параметри OCSP-сервера

	// Встановлення параметрів OCSP-сервера (див. табл. 3.1)
	def SetOCSPSettings (
		bUseOCSP:	EU_OCSP_SETTINGS)	// Вхідний. Параметри OCSP-сервера.
								// Усі поля повинні бути 
								// заповнені

	EUGetTSPSettings, EUSetTSPSettings
	// Отримання параметрів TSP-сервера (див. табл. 3.1)
	def GetTSPSettings (
		pbGetStamps:	EU_TSP_SETTINGS)	// Вихідний. Параметри 
// TSP-сервера

	// Встановлення параметрів TSP-сервера (див. табл. 3.1)
	def SetTSPSettings (
		bGetStamps:	EU_TSP_SETTINGS)	// Вхідний. Параметри TSP-сервера.
								// Усі поля повинні бути 
								// заповнені

	EUGetLDAPSettings, EUSetLDAPSettings
	// Отримання параметрів LDAP-сервера (див. табл. 3.1)
	def GetLDAPSettings (
		pbUseLDAP:	EU_LDAP_SETTINGS)		// Вихідний. Параметри LDAP-сервера

	// Встановлення параметрів LDAP-сервера (див. табл. 3.1)
	def SetLDAPSettings (
		bUseLDAP:	EU_ LDAP_SETTINGS)	// Вхідний. Параметри LDAP-сервера.
								// Усі поля повинні бути 
								// заповнені

	EUGetCMPSettings, EUSetCMPSettings
	// Отримання параметрів CMP-сервера
	def GetCMPSettings (
		pbUseCMP:	EU_CMP_SETTINGS)		// Вихідний. Параметри CMP-сервера

	// Встановлення параметрів CMP-сервера (див. табл. 3.1)
	def SetCMPSettings (
		bUseCMP:	EU_CMP_SETTINGS)		// Вхідний. Параметри CMP-сервера
								// Усі поля повинні бути 
								// заповнені

	EUGetOCSPAccessInfoModeSettings, EUSetOCSPAccessInfoModeSettings
	// Отримання інформації, щодо використання точок доступу до серверів OCSP
	def GetOCSPAccessInfoModeSettings (
		pbEnabled:	EU_OCSP_ACCESS_INFO_MODE_SETTINGS)	// Вихідний. 
								// Параметри використання 
								// точок доступу до серверів OCSP

	// Встановлення інформації, щодо використання точок доступу до серверів OCSP
	def SetOCSPAccessInfoModeSettings (
		bEnabled:	EU_OCSP_ACCESS_INFO_MODE_SETTINGS)	// Вхідний. 
								// Параметри використання 
								// точок доступу до серверів OCSP.
								// Усі поля повинні бути 
								// заповнені

	EUEnumOCSPAccessInfoSettings
	// Перелічення точок доступу до серверів OCSP
	def EnumOCSPAccessInfoSettings (
		dwIndex:		long,			// Вхідний. Порядковий номер точки
								// доступу до серверу OCSP
		pszIssuerCN:	EU_ OCSP_ACCESS_INFO _SETTINGS)	// Вихідний. 
								// Параметри доступу до серверу OCSP 
								// за реквізитами ЦСК. 

	EUGetOCSPAccessInfoSettings, EUSetOCSPAccessInfoSettings
	// Отримання параметрів доступу до серверу OCSP за реквізитами ЦСК
	def GetOCSPAccessInfoSettings (
		pszIssuerCN:	EU_ OCSP_ACCESS_INFO _SETTINGS)	// Вихідний. 
								// Параметри доступу до серверу OCSP 
								// за реквізитами ЦСК. 
								// Поле «szIssuerCN» повинно бути 
								// заповнене

	// Встановлення параметрів CMP-сервера (див. табл. 3.1)
	def SetOCSPAccessInfoSettings (
		pszIssuerCN:	EU_ OCSP_ACCESS_INFO _SETTINGS)	// Вхідний. 
								// Параметри доступу до серверу OCSP 
								// за реквізитами ЦСК. 
								// Усі поля повинні бути 
								// заповнені

	EUDeleteOCSPAccessInfoSettings
	// Видалення параметрів доступу до серверу OCSP за реквізитами ЦСК
	def DeleteOCSPAccessInfoSettings (
		pszIssuerCN:		unicode);	// Вхідний. Реквізити ЦСК

	EUSetRuntimeParameter
	// Функція конфігурації параметрів роботи криптографічної бібліотеки
	def SetRuntimeParameter (
		pszParameterName:		str,		// Вхідний. Ім'я параметру
		pvParameterValue:		Boolean (long))	// Вхідний. Значення параметру 
								// (може бути типу Boolean чи long)

І.5.2 Функції роботи з особистим ключем та носієм ключової інформації
	EUEnumKeyMediaTypes
	// Перелічення наявних типів НКІ
	def EnumKeyMediaTypes (
		dwTypeIndex:		long,		// Вхідний. Індекс типу НКІ
		pszTypeDescription:	list[unicode] // Вихідний. Опис типу НКІ
								// (записується за нулевим індексом)
	) -> Boolean 					// Результат. Якщо True – функція
								// виконана успішно, якщо False - 
								// перелік закінчено
	EUEnumKeyMediaDevices
	// Перелічення наявних НКІ вказаного типу
	def EnumKeyMediaDevices (
		dwTypeIndex			long,		// Вхідний. Індекс типу НКІ
		dwDeviceIndex		long,		// Вхідний. Індекс НКІ
		pszDeviceDescription:	list[unicode] // Вихідний. Назва НКІ
								// (записується за нулевим індексом)
	) -> Boolean 					// Результат. Якщо True – функція
								// виконана успішно, якщо False - 
								// перелік закінчено

	EUIsPrivateKeyReaded
	// Перевірка наявності зчитаного особистого ключа
	def IsPrivateKeyReaded ()-> Boolean

	EUReadPrivateKey
	// Зчитування особистого ключа (див. дод. Е.3)
	def ReadPrivateKey (
		pKeyMedia:	EU_KEY_MEDIA,		// Вхідний. Параметри носія 
								// особистого ключа
		pInfo:	EU_CERT_OWNER_INFO)	// Вихідний. Якщо не None записується
								// інформація про 
								// сертифікат власника

	EUReadPrivateKeyBinary
	// Зчитування особистого ключа у вигляді масиву байт
	def ReadPrivateKeyBinary (
		pbPrivateKey:		bytes,	// Вхідний. Особистий ключ у вигляді 
								// масиву байт
		dwPrivateKeyLength:	long,		// Вхідний. Довжина											// особистого ключа у вигляді масиву
								// байт
		pszPassword:		str,		// Вхідний. Пароль доступу до 
								// особистого ключа
		pInfo:	EU_CERT_OWNER_INFO)	// Вихідний. Якщо не None записується
								// інформація про 
								// сертифікат власника

	EUReadPrivateKeyFile
	// Зчитування особистого ключа з файлу
	def ReadPrivateKeyFile (
		pszPrivateKeyFileName:	str,		// Вхідний. Ім`я файлу з 
								// особистим ключем
		pszPassword:		str,		// Вхідний. Пароль доступу до 
								// особистого ключа
		pInfo:	EU_CERT_OWNER_INFO)	// Вихідний. Якщо не None записується
								// інформація про 
								// сертифікат власника

	EUResetPrivateKey
	// Затирання особистого ключа у пам’яті
	def ResetPrivateKey ();

	EUEnumOwnCertificates
	// Перелічення наявних сертифікатів користувача
	def EnumOwnCertificates (
		dwIndex		long,			// Вхідний. Індекс сертифіката
		ppInfo:		EU_CERT_INFO_EX);	// Вихідний. Записується детальна
								// інформація про сертифікат

І.5.3 Функції хешування
	EUHashData
	//Формування геша даних
	def HashData (
		pbData:		bytes,		// Вхідний. Дані для геша
		dwDataLength:	long,			// Вхідний. Розмір даних для геша
		ppszHash:		list[bytes],	// Вихідний. Геш у 
								// вигляді BASE64-строки (записується
								// за нулевим індексом). Якщо
								// параметр дорівнює None, геш									// повертається у вигляді масиву байт
		ppbHash:		list[bytes])	// Вихідний. Геш у вигляді 
								// масиву байт (записується
								// за нулевим індексом)

	EUHashDataContinue
	// Ітеративне формування гешІ. Функція може викликатися необмежену 
	// кількість раз. Для завершення ітеративного формування геша необхідно 
	// викликати функцію HashDataEnd
	def HashDataContinue (
		pbData:		bytes,		// Вхідний. Дані для геша
		dwDataLength:	long)			// Вхідний. Розмір даних для геша

	EUHashDataEnd
	// Завершення ітеративного формування геша
	def HashDataEnd (
		ppszHash:		list[bytes],	// Вихідний. Геш у 
								// вигляді BASE64-строки (записується
								// за нулевим індексом). Якщо
								// параметр дорівнює None, геш									// повертається у вигляді масиву байт
		ppbHash:		list[bytes])	// Вихідний. Геш у вигляді 
								// масиву байт (записується
								// за нулевим індексом)

	EUHashFile
	// Обчислення геша файла 
	def HashFile (
		pszFileName:	str,			// Вхідний. Ім’я файлу з даними
		ppszHash:		list[bytes],	// Вихідний. Геш у 
								// вигляді BASE64-строки (записується
								// за нулевим індексом). Якщо
								// параметр дорівнює None, геш									// повертається у вигляді масиву байт
		ppbHash:		list[bytes])	// Вихідний. Геш у вигляді 
								// масиву байт (записується
								// за нулевим індексом)

	EUHashDataWithParams
	//Формування геша даних. Параметри геш обираються з сертифікату
	def HashDataWithParams (
		pbCertificate:		bytes,	// Вхідний. Сертифікат
		dwCertificateLength:	long,		// Вхідний. Розмір
								// сертифікату
		pbData:		bytes,		// Вхідний. Дані для геша
		dwDataLength:	long,			// Вхідний. Розмір даних для геша
		ppszHash:		list[bytes],	// Вихідний. Геш у 
								// вигляді BASE64-строки (записується
								// за нулевим індексом). Якщо
								// параметр дорівнює None, геш									// повертається у вигляді масиву байт
		ppbHash:		list[bytes])	// Вихідний. Геш у вигляді 
								// масиву байт (записується
								// за нулевим індексом)

	EUHashDataBeginWithParams
	// Початок ітеративного формування геша. Параметри геш обираються з
	// сертифікату. Функція може викликатися необмежену кількість раз. Для 
	// продовження ітеративного формування геша необхідно викликати функцію
	// HashDataContinue. Для завершення ітеративного формування геша необхідно
	// викликати функцію HashDataEnd.
	def HashDataBeginWithParams (
		pbCertificate:		bytes,	// Вхідний. Сертифікат
		dwCertificateLength:	long)		// Вхідний. Розмір
								// сертифікату

	EUHashDataFileWithParams
	// Обчислення геша файлІ. Параметри геш обираються з сертифікату 
	def HashFileWithParams (
		pbCertificate:		bytes,	// Вхідний. Сертифікат
		dwCertificateLength:	long,		// Вхідний. Розмір
								// сертифікату
		pszFileName:	str,			// Вхідний. Ім’я файлу з даними
		ppszHash:		list[bytes],	// Вихідний. Геш у 
								// вигляді BASE64-строки (записується
								// за нулевим індексом). Якщо
								// параметр дорівнює None, геш									// повертається у вигляді масиву байт
		ppbHash:		list[bytes])	// Вихідний. Геш у вигляді 
								// масиву байт (записується
								// за нулевим індексом)

І.5.4 Функції ЕЦП

	EUSignData
	// Формування зовнішнього (підпис знаходиться окремо від даних) електронного 
	// цифрового підпису (ЕЦП) 
	def SignData (
		pbData:		bytes,		// Вхідний. Дані для підпису
		dwDataLength:	long,			// Вхідний. Розмір даних для підпису
		ppszSign:		list[bytes],	// Вихідний. Підпис у вигляді 
								// BASE64-строки (записується за
								// нулевим індексом). Якщо параметр
								// дорівнює None, повертається підпис
								// у вигляді масиву байт
		ppbSign:		list[bytes])	// Вихідний. Підпис у вигляді масиву 
								// байт (записується
								// за нулевим індексом)


	EUVerifyData
	// Перевірка зовнішнього ЕЦП
	def VerifyData (
		pbData:		bytes,		// Вхідний. Дані для перевірки ЕЦП
		dwDataLength:	long,			// Вхідний. Розмір даних для 
								// перевірки ЕЦП
		pszSign:		bytes,		// Вхідний. Підпис для перевірки у 
								// вигляді BASE64-строки. Якщо 
								// параметр дорівнює None, 
								// перевіряється 
								// підпис у вигляді масиву байт
		pbSign:		bytes,		// Вхідний. Підпис у вигляді масиву 
								// байт
		dwSignLength:	long,			// Вхідний. Розмір підпису у 
								// вигляді масиву байт
		pSignInfo:		EU_SIGN_INFO)	// Вихідний. Якщо не None записується
								// інформація про підпис


	EUSignDataInternal
	// Формування внутрішнього (підпис знаходиться разом з даними) ЕЦП
	def SignDataInternal (
		bAppendCert:	Boolean,		// Вхідний. Включати сертифікат
								// підписувача у підписані дані
		pbData:		bytes,		// Вхідний. Дані для підпису
		dwDataLength:	long,			// Вхідний. Розмір даних для підпису
		ppszSignedData:	list[bytes],	// Вихідний. Підписані дані у 
								// вигляді BASE64-строки (записується
								// за нулевим індексом). Якщо
								// параметр дорівнює None, 
								// повертається підпис у вигляді
								// масиву байт
		ppbSignedData:	list[bytes])	// Вихідний. Підпис у вигляді 
								// масиву байт (записується
								// за нулевим індексом)

	EUVerifyDataInternal
	// Перевірка внутрішнього ЕЦП
	def VerifyDataInternal (
		pszSignedData:		bytes,	// Вхідний. Підписані дані для 									// перевірки у вигляді BASE64-строки. 
								// Якщо  параметр дорівнює None, 
								// перевіряються підписані дані у 
								// вигляді масиву байт
		pbSignedData:		bytes,	// Вхідний. Підписані дані у 
								// вигляді масиву байт
		dwSignedDataLength:	long,		// Вхідний. Розмір підпису у 
								// вигляді масиву байт
		ppbData:			list[bytes],// Вихідний. Отримані після перевірки
								// ЕЦП дані(записується за
								// нулевим індексом)
		pSignInfo:		EU_SIGN_INFO)	// Вихідний. Якщо не None записується
								// інформація про підпис

	EUSignHash
	// Формування підпису геша
	def SignHash (
		pszHash:		bytes,		// Вхідний. Геш у вигляді
								// BASE64-строки. Якщо параметр
								// дорівнює None, геш у вигляді
								// масиву байт
		pbHash:		bytes,		// Вхідний. Геш у вигляді масиву байт
		dwHashLength:	long,			// Вхідний. Розмір гешу
		ppszSign:		list[bytes],	// Вихідний. Підпис у вигляді 
								// BASE64-строки (записується за
								// нулевим індексом). Якщо параметр
								// дорівнює None, повертається підпис
								// у вигляді масиву байт
		ppbSign:		list[bytes])	// Вихідний. Підпис у вигляді масиву 
								// байт (записується
								// за нулевим індексом)

	EUVerifyHash
	// Перевірка підпису геша
	def VerifyHash (
		pszHash:		bytes,		// Вхідний. Геш у вигляді
								// BASE64-строки. Якщо параметр
								// дорівнює None, геш у вигляді
								// масиву байт
		pbHash:		bytes,		// Вхідний. Геш у вигляді масиву байт
		dwHashLength:	long,			// Вхідний. Розмір гешу
		pszSign:		bytes,		// Вхідний. Підпис для перевірки у 
								// вигляді BASE64-строки. Якщо 
								// параметр дорівнює None, 
								// перевіряється 
								// підпис у вигляді масиву байт
		pbSign:		bytes,		// Вхідний. Підпис у вигляді масиву 
								// байт
		dwSignLength:	long,			// Вхідний. Розмір підпису у 
								// вигляді масиву байт
		pSignInfo:		EU_SIGN_INFO)	// Вихідний. Якщо не None записується
								// інформація про підпис

	EURawSignData
	// Формування спрощеного (порядковий номер сертифіката, дата підпису та підпис; 
	// знаходиться окремо від даних) ЕЦП
	// Примітка. В наступних версіях бібліотеки функція буде видалена, тому що
	// формат підпису не відповідає вимогам законодавства
	def RawSignData (
		pbData:		bytes,		// Вхідний. Дані для підпису
		dwDataLength:	long,			// Вхідний. Розмір даних для підпису
		ppszSign:		list[bytes],	// Вихідний. Підпис у вигляді 
								// BASE64-строки (записується за
								// нулевим індексом). Якщо параметр
								// дорівнює None, повертається підпис
								// у вигляді масиву байт
		ppbSign:		list[bytes])	// Вихідний. Підпис у вигляді масиву 
								// байт (записується
								// за нулевим індексом)

	EURawVerifyData
	// Перевірка спрощеного ЕЦП
	// Примітка. В наступних версіях бібліотеки функція буде видалена, тому що
	// формат підпису не відповідає вимогам законодавства
	def RawVerifyData (
		pbData:		bytes,		// Вхідний. Дані для перевірки ЕЦП
		dwDataLength:	long,			// Вхідний. Розмір даних для 
								// перевірки ЕЦП
		pszSign:		bytes,		// Вхідний. Підпис для перевірки у 
								// вигляді BASE64-строки. Якщо 
								// параметр дорівнює None, 
								// перевіряється 
								// підпис у вигляді масиву байт
		pbSign:		bytes,		// Вхідний. Підпис у вигляді масиву 
								// байт
		dwSignLength:	long,			// Вхідний. Розмір підпису у 
								// вигляді масиву байт
		pSignInfo:		EU_SIGN_INFO)	// Вихідний. Якщо не None записується
								// інформація про підпис

	EURawSignHash
	// Формування спрощеного ЕЦП від гешу
	// Примітка. В наступних версіях бібліотеки функція буде видалена, тому що
	// формат підпису не відповідає вимогам законодавства
	def RawSignHash (
		pszHash:		bytes,		// Вхідний. Геш у вигляді
								// BASE64-строки. Якщо параметр
								// дорівнює None, геш у вигляді
								// масиву байт
		pbHash:		bytes,		// Вхідний. Геш у вигляді масиву байт
		dwHashLength:	long,			// Вхідний. Розмір гешу
		ppszSign:		list[bytes],	// Вихідний. Підпис у вигляді 
								// BASE64-строки (записується за
								// нулевим індексом). Якщо параметр
								// дорівнює None, повертається підпис
								// у вигляді масиву байт
		ppbSign:		list[bytes])	// Вихідний. Підпис у вигляді масиву 
								// байт (записується
								// за нулевим індексом)

	EURawVerifyHash
	// Перевірка спрощеного ЕЦП від гешу
	// Примітка. В наступних версіях бібліотеки функція буде видалена, тому що
	// формат підпису не відповідає вимогам законодавства
	def DWORD (WINAPI *PEU_RAW_VERIFY_HASH)(
		pszHash:		bytes,		// Вхідний. Геш у вигляді
								// BASE64-строки. Якщо параметр
								// дорівнює None, геш у вигляді
								// масиву байт
		pbHash:		bytes,		// Вхідний. Геш у вигляді масиву байт
		dwHashLength:	long,			// Вхідний. Розмір гешу
		pszSign:		bytes,		// Вхідний. Підпис для перевірки у 
								// вигляді BASE64-строки. Якщо 
								// параметр дорівнює None, 
								// перевіряється 
								// підпис у вигляді масиву байт
		pbSign:		bytes,		// Вхідний. Підпис у вигляді масиву 
								// байт
		dwSignLength:	long,			// Вхідний. Розмір підпису у 
								// вигляді масиву байт
		pSignInfo:		EU_SIGN_INFO)	// Вихідний. Якщо не None записується
								// інформація про підпис

	EURawSignFile
	// Формування спрощеного ЕЦП файлу
	// Примітка. В наступних версіях бібліотеки функція буде видалена, тому що
	// формат підпису не відповідає вимогам законодавства
	def RawSignFile (
		pszFileName:		str,		// Вхідний. Ім’я файлу з даними
		pszFileNameWithSign:	str)		// Вхідний. Ім’я файлу, в 
								// який необхідно записати 
								// спрощений підпис у вигляді 
								// BASE64-строки

	EURawVerifyFile
	// Перевірка спрощеного ЕЦП файлу
	// Примітка. В наступних версіях бібліотеки функція буде видалена, тому що
	// формат підпису не відповідає вимогам законодавства
	def RawVerifyFile (
		pszFileNameWithSign:	str,		// Вхідний. Ім’я файлу 
								// зі спрощеним підписом у вигляді 
								// BASE64-строки
		pszFileName:		str,		// Вхідний. Ім’я файлу з даними
		pSignInfo:		EU_SIGN_INFO)	// Вихідний. Якщо не None записується
								// інформація про підпис


	EUGetSignsCount
	// Отримання кількості ЕЦП, що містяться в підписаних даних
	def GetSignsCount (
		pszSign:		bytes,		// Вхідний. Підпис для перевірки у 
								// вигляді BASE64-строки. Якщо 
								// параметр дорівнює None, 
								// перевіряється 
								// підпис у вигляді масиву байт
		pbSign:		bytes,		// Вхідний. Підпис у вигляді масиву 
								// байт
		dwSignLength:	long,			// Вхідний. Розмір підпису у 
								// вигляді масиву байт
		pdwCount:		list[long]);	// Вихідний. Кількість ЕЦП у 
								// підписаних даних (записується за
								// нулевим індексом)

	EUGetSignerInfo
	// Отримання розширеної інформації про підписувача
	def GetSignerInfo (
		dwSignIndex		long,			// Вхідний. Індекс ЕЦП для перевірки
		pszSign:		bytes,		// Вхідний. Підпис для перевірки у 
								// вигляді BASE64-строки. Якщо 
								// параметр дорівнює None, 
								// перевіряється 
								// підпис у вигляді масиву байт
		pbSign:		bytes,		// Вхідний. Підпис у вигляді масиву 
								// байт
		dwSignLength:	long,			// Вхідний. Розмір підпису у 
								// вигляді масиву байт
		ppInfo:		EU_CERT_INFO_EX,	// Вихідний. Записується інформація
								// про сертифікат
		ppbCertificate:	list[bytes])	// Вихідний. Сертифікат 
								// підписувача у вигляді масиву байт 
								// (записується за нулевим індексом)


	EUGetFileSignsCount
	// Отримання кількості ЕЦП, що містить підписаний файл (Примітка: Розмір файла 
	// не обмежений)
	def GetFileSignsCount (
		pszFileNameWithSign:	str,		// Вхідний. Ім’я файлу з 
								// підписаними даними 
		pdwCount:			list[long]);// Вихідний. Кількість ЕЦП у 
								// підписаних даних (записується за
								// нулевим індексом)

	EUGetFileSignerInfo
	// Отримання розширеної інформації про підписувача для файлу
	def GetFileSignerInfo (
		dwSignIndex			long,		// Вхідний. Індекс ЕЦП для перевірки
		pszFileNameWithSign:	str,		// Вхідний. Ім’я файлу з 
								// підписаними даними 
		ppInfo:		EU_CERT_INFO_EX,	// Вихідний. Записується інформація
								// про сертифікат
		ppbCertificate:	list[bytes])	// Вихідний. Сертифікат 
								// підписувача у вигляді масиву байт 
								// (записується за нулевим індексом)


	EUVerifyHashOnTimeEx
	// Перевірка підпису геша для заданого часу.
	// Час перевірки задається за допомоги параметру pOnTime. Значення параметру 
	// pOnTime, буде використано лише у випадку коли у підписі відсутній час 
	// підпису або мітка часу. Якщо значення параметру pOnTime дорівнює NULL, 
	// використовується час підпису або мітка часу, що містяться в підписі або у 
	// разі їх відсутності поточний час ОС. При встановленні параметру bOffline
	// (bOffline = TRUE) перевірка сертифікату підписувача відбувається без 
	// використання онлайн сервісів незалежно від налаштувань бібліотеки, якщо 
	// bOffline = FALSE, використовуються налаштування бібліотеки. При встановленні 
	// параметру bNoCRL (bNoCRL = TRUE) перевірка сертифікату підписувача 
	// відбувається без використання СВС незалежно від налаштувань бібліотеки, якщо 
	// bNoCRL = FALSE, використовуються налаштування бібліотеки.
	def VerifyHashOnTimeEx
		pszHash:		bytes,		// Вхідний. Геш у вигляді
								// BASE64-строки. Якщо параметр
								// дорівнює None, геш у вигляді
								// масиву байт
		pbHash:		bytes,		// Вхідний. Геш у вигляді масиву байт
		dwHashLength:	long,			// Вхідний. Розмір гешу
		dwSignIndex:	long,			// Вхідний. Індекс ЕЦП для перевірки
		pszSign:		bytes,		// Вхідний. Підпис для перевірки у 
								// вигляді BASE64-строки. Якщо 
								// параметр дорівнює None, 
								// перевіряється 
								// підпис у вигляді масиву байт
		pbSign:		bytes,		// Вхідний. Підпис у вигляді масиву 
								// байт
		dwSignLength:	long,			// Вхідний. Розмір підпису у 
								// вигляді масиву байт
		pOnTime:		SYSTEMTIME,		// Вхідний. Час підпису для перевірки
		bOffline:		Boolean,		// Вхідний. Признак необхідності не 
								// використовувати онлайн-сервіси
		bNoCRL:		Boolean,		// Вхідний. Признак необхідності не 
								// використовувати СВС
		pSignInfo:		EU_SIGN_INFO)	// Вихідний. Якщо не None записується
								// інформація про підпис

	EUVerifyDataOnTimeEx
	// Перевірка зовнішнього підпису даних для заданого часу.
	// Час перевірки задається за допомоги параметру pOnTime. Значення параметру 
	// pOnTime, буде використано лише у випадку коли у підписі відсутній час 
	// підпису або мітка часу. Якщо значення параметру pOnTime дорівнює NULL, 
	// використовується час підпису або мітка часу, що містяться в підписі або у 
	// разі їх відсутності поточний час ОС. При встановленні параметру bOffline
	// (bOffline = TRUE) перевірка сертифікату підписувача відбувається без 
	// використання онлайн сервісів незалежно від налаштувань бібліотеки, якщо 
	// bOffline = FALSE, використовуються налаштування бібліотеки. При встановленні 
	// параметру bNoCRL (bNoCRL = TRUE) перевірка сертифікату підписувача 
	// відбувається без використання СВС незалежно від налаштувань бібліотеки, якщо 
	// bNoCRL = FALSE, використовуються налаштування бібліотеки.
	def VerifyDataOnTimeEx (
		pbData:		bytes,		// Вхідний. Дані для перевірки ЕЦП
		dwDataLength:	long,			// Вхідний. Розмір даних для 
								// перевірки ЕЦП
		dwSignIndex:	long,			// Вхідний. Індекс ЕЦП для перевірки
		pszSign:		bytes,		// Вхідний. Підпис для перевірки у 
								// вигляді BASE64-строки. Якщо 
								// параметр дорівнює None, 
								// перевіряється 
								// підпис у вигляді масиву байт
		pbSign:		bytes,		// Вхідний. Підпис у вигляді масиву 
								// байт
		dwSignLength:	long,			// Вхідний. Розмір підпису у 
								// вигляді масиву байт
		pOnTime:		SYSTEMTIME,		// Вхідний. Час підпису для перевірки
		bOffline:		Boolean,		// Вхідний. Признак необхідності не 
								// використовувати онлайн-сервіси
		bNoCRL:		Boolean,		// Вхідний. Признак необхідності не 
								// використовувати СВС
		pSignInfo:		EU_SIGN_INFO)	// Вихідний. Якщо не None записується
								// інформація про підпис

	EUVerifyDataInternalOnTimeEx
	// Перевірка внутрішнього підпису даних для заданого часу.
	// Час перевірки задається за допомоги параметру pOnTime. Значення параметру 
	// pOnTime, буде використано лише у випадку коли у підписі відсутній час 
	// підпису або мітка часу. Якщо значення параметру pOnTime дорівнює NULL, 
	// використовується час підпису або мітка часу, що містяться в підписі або у 
	// разі їх відсутності поточний час ОС. При встановленні параметру bOffline
	// (bOffline = TRUE) перевірка сертифікату підписувача відбувається без 
	// використання онлайн сервісів незалежно від налаштувань бібліотеки, якщо 
	// bOffline = FALSE, використовуються налаштування бібліотеки. При встановленні 
	// параметру bNoCRL (bNoCRL = TRUE) перевірка сертифікату підписувача 
	// відбувається без використання СВС незалежно від налаштувань бібліотеки, якщо 
	// bNoCRL = FALSE, використовуються налаштування бібліотеки.
	def VerifyDataInternalOnTimeEx (
		dwSignIndex:		long,		// Вхідний. Індекс ЕЦП для перевірки
		pszSignedData:		bytes,	// Вхідний. Підписані дані для 									// перевірки у вигляді BASE64-строки. 
								// Якщо  параметр дорівнює None, 
								// перевіряються підписані дані у 
								// вигляді масиву байт
		pbSignedData:		bytes,	// Вхідний. Підписані дані у 
								// вигляді масиву байт
		dwSignedDataLength:	long,		// Вхідний. Розмір підпису у 
								// вигляді масиву байт
		pOnTime:			SYSTEMTIME,	// Вхідний. Час підпису для перевірки
		bOffline:			Boolean,	// Вхідний. Признак необхідності не 
								// використовувати онлайн-сервіси
		bNoCRL:			Boolean,	// Вхідний. Признак необхідності не 
								// використовувати СВС
		ppbData:			list[bytes],// Вихідний. Отримані після перевірки
								// ЕЦП дані (записується за
								// нулевим індексом)
		pSignInfo:		EU_SIGN_INFO)	// Вихідний. Якщо не None записується
								// інформація про підпис

	EUIsDataInSignedDataAvailable
	// Отримання інформації про наявність даних в підписаних даних
	def IsDataInSignedDataAvailable (
		pszSignedData:		bytes,	// Вхідний. Підписані дані для 									// перевірки у вигляді BASE64-строки. 
								// Якщо  параметр дорівнює None, 
								// перевіряються підписані дані у 
								// вигляді масиву байт
		pbSignedData:		bytes,	// Вхідний. Підписані дані у 
								// вигляді масиву байт
		dwSignedDataLength:	long,		// Вхідний. Розмір підпису у 
								// вигляді масиву байт
pbAvailable:		list[Boolean]);	// Вихідний. Інформація про 
								// наявність даних в підписі. Якщо 
								// TRUE - підпис внутрішній, в іншому 
						// випадку підпис зовнішній 
								//(записується за нулевим індексом)

	EUIsDataInSignedFileAvailable
	// Отримання інформації про наявність даних в підписаних даних
	def IsDataInSignedFileAvailable (
		pszFileNameWithSignedData:	str,		// Вхідний. Ім’я файлу 
								// з підписаними даними
pbAvailable:		list[Boolean]);	// Вихідний. Інформація про 
								// наявність даних в підписі. Якщо 
								// TRUE - підпис внутрішній, в іншому 
						// випадку підпис зовнішній 
								//(записується за нулевим індексом)

	EUGetDataFromSignedData
	// Отримання даних, що містяться в підписаних даних
	def GetDataFromSignedData (
		pszSignedData:		bytes,	// Вхідний. Підписані дані для 									// перевірки у вигляді BASE64-строки. 
								// Якщо  параметр дорівнює None, 
								// перевіряються підписані дані у 
								// вигляді масиву байт
		pbSignedData:		bytes,	// Вхідний. Підписані дані у 
								// вигляді масиву байт
		dwSignedDataLength:	long,		// Вхідний. Розмір підпису у 
								// вигляді масиву байт
		ppbData:			list[bytes]),// Вихідний. Отримані після 
								// перевірки ЕЦП дані(записується за
								// нулевим індексом)

	EUCreateEmptySign
	// Створення порожнього підпису 
	def CreateEmptySign (
		pbData:		bytes,		// Вхідний. Дані, що підписуються, 
								// якщо pbData = None - підпис
								// зовнішній, інакше внутрішній
		dwDataLength:	long,			// Вхідний. Розмір даних, що 
								// підписуються
		ppszSign:		list[bytes],	// Вихідний. Підпис у вигляді 
								// BASE64-строки (записується за
								// нулевим індексом). Якщо параметр
								// дорівнює None, повертається підпис
								// у вигляді масиву байт
		ppbSign:		list[bytes])	// Вихідний. Порожній підпис у 
								// вигляді масиву байт (записується
								// за нулевим індексом)

	EUAppendSigner
	// Додавання інформації про підписувача до підпису 
	def AppendSigner (
		pszSigner:			bytes,	// Вхідний. Інформація про 
								// підписувача у вигляді
								// BASE64-строки. Якщо параметр 
								// дорівнює None, передається 
								// інформація про підписувача у 
								// вигляді масиву байт
		pbSigner:			bytes,	// Вхідний. Інформація про 
								// підписувача у вигляді масиву байт
		dwSignerLength:		long,		// Вхідний. Розмір інформації 
								// про підписувача у вигляді масиву
								// байт
		pbCertificate:		bytes,	// Вхідний. Сертифікат підписувача.
								// Якщо параметр дорівнює None
								// сертифікат до підпису не додається
		dwCertificateLength:	long,		// Вхідний. Розмір
								// сертифіката підписувача.
		pszPreviousSign:		bytes,	// Вхідний. Попередній підпис у 
								// вигляді BASE64-строки. Ящко None 
								// попередній підпис передається у 
								// вигляді масиву байт
		pbPreviousSign:		bytes,	// Вхідний. Попередній підпис у 
								// вигляді масиву байт. None, якщо 
								// попередній підпис передається у 
								// вигляді BASE64-строки
		dwPreviousSignLength:	long,		// Вхідний. Розмір 
								// попереднього підпис у вигляді
								// масиву байт.
		ppszSign:			list[bytes],// Вихідний. Підпис у вигляді 
								// BASE64-строки (записується за
								// нулевим індексом). Якщо параметр
								// дорівнює None, повертається підпис
								// у вигляді масиву байт
		ppbSign:			list[bytes])// Вихідний. Порожній підпис у 
								// вигляді масиву байт (записується
								// за нулевим індексом)

	EUGetSigner
	// Отримання інформації про підписувача 
	def GetSigner (
		dwSignIndex:		long,		// Вхідний. Індекс ЕЦП
		pszSign:			bytes,	// Вхідний. Підпис у 
								// вигляді BASE64-строки. Якщо 
								// параметр дорівнює None, 
								// передається  підпис у вигляді 
								// масиву байт
		pbSign:			bytes,	// Вхідний. Підпис у вигляді масиву 
								// байт
		dwSignLength:		long,		// Вхідний. Розмір підпису у 
								// вигляді масиву байт
		ppszSigner:			list[bytes],// Вихідний. Інформація про 
								// підписувача у вигляді
								// BASE64-строки (записується за 
								// нулевим індексом). Якщо параметр 
								// дорівнює None, повертається 
								// інформація про підписувача у 
								// вигляді масиву байт
		ppbSigner:			list[bytes])// Вихідний. Інформація про 
								// підписувача у вигляді масиву байт 
								// (записується за нулевим індексом)

	EUGetFileSigner
	// Отримання розширеної інформації про підписувача для файлу 
	def GetFileSigner (
		dwSignIndex:		long,		// Вхідний. Індекс ЕЦП
		pszFileNameWithSign:	str,		// Вхідний. Ім’я файлу з 
								// підписаними даними 
		ppszSigner:			list[bytes],// Вихідний. Інформація про 
								// підписувача у вигляді
								// BASE64-строки (записується за
								// нулевим індексом). Якщо параметр 
								// дорівнює None, повертається 
								// інформація про підписувача у 
								// вигляді масиву байт
		ppbSigner:			list[bytes])// Вихідний. Інформація про 
								// підписувача у вигляді масиву байт 
								// (записується за нулевим індексом)



І.5.5 Функції роботи з сховищем сертифікатів та СВС
	EUGetCertificateInfoEx
	// Отримання детальної інформації(розширеної) про сертифікат
	def GetCertificateInfoEx (
		pszIssuer:		str,			// Вхідний. Реквізити ЦСК
		pszSerial:		str,			// Вхідний. Серійний номер 
								// сертифіката
		ppInfo:		EU_CERT_INFO_EX);	// Вихідний. Записується детальна
								// інформація про сертифікат

	EUParseCertificateEx
	// Отримання розширеної інформації про сертифікат
	def ParseCertificateEx (
		pbCertificate:		bytes,	// Вхідний. Сертифікат у вигляді 
								// масиву байт
		dwCertificateLength:	long,		// Вхідний. Довжина 
								// сертифіката у вигляді масиву байт
		ppInfo:		EU_CERT_INFO_EX);	// Вихідний. Записується детальна
								// інформація про сертифікат

	EUGetCRInfo
	// Отримання інформації про запит на сертифікат
	def GetCRInfo (
		pbRequest:		bytes,		// Вхідний. Запит на отримання
								// сертифіката у вигляді масиву байт
		dwRequest:		long,			// Вхідний. Розмір запит на отримання
								// сертифіката у вигляді масиву байт
		ppInfo:		EU_CR_INFO)		// Вихідний. Записується інформація
								// про запит на сертифікат

	EUGetCertificate
	// Отримання сертифіката користувача
	def GetCertificate (
		pszIssuer:		str,			// Вхідний. Реквізити ЦСК
		pszSerial:		str,			// Вхідний. Серійний номер 
								// сертифіката
		ppszCertificate:	list[bytes],	// Вихідний. Сертифікат 
								// у вигляді BASE64-строки
								// (записується за нулевим індексом). 
								// Якщо параметр дорівнює None, 
								// сертифікат повертаються
								// у вигляді масиву байт
		ppbCertificate:	list[bytes])	// Вихідний. Сертифікат 
								// у вигляді масиву байт 
								// (записується за нулевим індексом)

І.5.6 Функції направленого шифрування

	EUDevelopData
	// Розшифрування даних
	def DevelopData (
		pszEnvelopedData:		bytes,	// Вхідний. Зашифровані дані у
								// вигляді BASE64-строки. Якщо 
								// параметр дорівнює None, 
								// зашифровані дані передаються у
								// вигляді масиву байт
		pbEnvelopedData:		bytes,	// Вхідний. Зашифровані дані у 
								// вигляді масиву байт 
		dwEnvelopedDataLength:	long,		// Вхідний. Розмір 
								// зашифрованих даних у вигляді 
								// масиву байт
		ppbData:			list[bytes],// Вихідний. Розшифровані дані для у 
								// вигляді масиву байт (записується
								// за нулевим індексом)
		pInfo:		EU_ENVELOP_INFO)	// Вихідний. Якщо не None записується
								// інформація про 
								// відправника зашифрованих даних

	EUDevelopFile
	//Розшифрування файлу (Примітка: Розмір файла не обмежений)
	def DevelopFile (
		pszEnvelopedFileName:	str,		// Вхідний. Ім’я файлу з
								// зашифрованими даними
		pszFileName:		str,		// Вхідний. Ім’я файлу 
								// в який необхідно записати
								// розшифровані дані
		pInfo:		EU_ENVELOP_INFO)	// Вихідний. Якщо не None записується
								// інформація про 
								// відправника зашифрованих даних

	EUEnvelopDataToRecipients
	// Зашифрування даних одночасно на декількох одержувачів. Дані зашифровуються
	// з використанням ключа ГОСТ-28147, після чого ключ зашифровується направлено 
	// для кожного з абонентів
	def EnvelopDataToRecipients (
		dwRecipientCerts:		list[bytes],// Вхідний. Список сертифікатів
								// одержувачів у вигліді масиву байт
		bSignData:			Boolean,	// Вхідний. Признак необхідності 
								// додатково підписувати дані
		pbData:			bytes,	// Вхідний. Дані для зашифрування у 
								// вигляді масиву байт
		dwDataLength:		long,		// Вхідний. Розмір даних у вигляді
								// масиву байт
		ppszEnvelopedData:	list[bytes],// Вихідний. Зашифровані дані 
								// у вигляді BASE64-строки
								// (записується за нулевим індексом). 
								// Якщо параметр дорівнює None, 
								// зашифровані дані повертаються
								// у вигляді масиву байт
		ppbEnvelopedData:		list[bytes])// Вихідний. Зашифровані дані 
								// у вигляді масиву байт (записується 
								// за нулевим індексом)

	EUEnvelopFileToRecipients
	// Зашифрування файла одночасно на декількох одержувачів. Файл зашифровується
	// з використанням ключа ГОСТ-28147, після чого ключ зашифровується направлено 
	// для кожного з абонентів (Примітка: Розмір файла не обмежений)
	def EnvelopFileToRecipients (
		dwRecipientCerts:		list[bytes],// Вхідний. Список сертифікатів
								// одержувачів у вигліді масиву байт
		bSignData:			Boolean,	// Вхідний. Признак необхідності 
								// додатково підписувати дані
		pszFileName:		str,		// Вхідний. Ім’я файлу з даними
		pszEnvelopedFileName:	str)		// Вхідний. Ім’я файлу 
								// в який необхідно записати 
								// зашифровані дані

	EUEnvelopDataToRecipientsOffline
	// Зашифрування даних одночасно на декількох одержувачів.
	// Дані зашифровуються з використанням ключа ГОСТ-28147, після чого ключ 
	// зашифровується направлено для кожного з абонентів
	def EnvelopDataToRecipientsOffline (
		dwRecipientCerts:		list[bytes],// Вхідний. Список сертифікатів
								// одержувачів у вигліді масиву байт
		bSignData:			Boolean,	// Вхідний. Признак необхідності 
								// додатково підписувати дані
		pbData:			bytes,	// Вхідний. Дані для зашифрування у 
								// вигляді масиву байт
		dwDataLength:		long,		// Вхідний. Розмір даних у вигляді
								// масиву байт
		bOffline:			Boolean,	// Вхідний. Признак необхідності 
								// примусово використовувати offline 
								// режим при перевірці сертифікатів 
								// одержувачів. Якщо FALSE - 
								// використовуються налаштування 
								// бібліотеки
		bNoCRL:			Boolean,	// Вхідний. Признак необхідності 
								// не використовувати СВС при
								// перевірці сертифікатів одержувачів
								// Якщо FALSE - використовуються
								// налаштування бібліотеки
		ppszEnvelopedData:	list[bytes],// Вихідний. Зашифровані дані 
								// у вигляді BASE64-строки
								// (записується за нулевим індексом). 
								// Якщо параметр дорівнює None, 
								// зашифровані дані повертаються
								// у вигляді масиву байт
		ppbEnvelopedData:		list[bytes])// Вихідний. Зашифровані дані 
								// у вигляді масиву байт (записується 
								// за нулевим індексом)

	EUEnvelopDataExWithDynamicKey
	// Зашифрування даних одночасно на декількох одержувачів за допомоги 
	// динамічного ключа протоколу розподілу ключів відправника. Дані 
	// зашифровуються з використанням ключа ГОСТ-28147, після чого ключ 
	// зашифровується направлено для кожного з абонентів з використанням динамічно 
	// згенерованого ключа протоколу розподілу ключів відправника.
	def EnvelopDataExWithDynamicKey (
		pszRecipientCertIssuers: list[unicode], // Вхідний. Реквізити 
								// ЦСК сертифікатів одержувачів.
// Якщо кількість 
								// реквізитів ЦСК менша за кількість 
								// серійних номерів сертифікатів 
								// одержувачів останній реквізит ЦСК 
								// в рядку буде використано для 
								// серійних номерів, що лишилися
		pszRecipientCertSerials: list[unicode], // Вхідний. Серійні 
								// номера сертифікатів одержувачів
		bSignData:			Boolean,	// Вхідний. Признак необхідності 
								// додатково підписувати дані
		bAppendCert:		Boolean,	// Вхідний. Включати сертифікат
								// підписувача у підписані дані
		pbData:			bytes,	// Вхідний. Дані для зашифрування у 
								// вигляді масиву байт
		dwDataLength:		long,		// Вхідний. Розмір даних у вигляді
								// масиву байт
		ppszEnvelopedData:	list[bytes], // Вихідний. Зашифровані дані 
								// у вигляді BASE64-строки 
								// (записується за нулевим індексом).
								// Якщо параметр дорівнює None, 
								// зашифровані дані повертаються
								// у вигляді масиву байт
		ppbEnvelopedData:		list[bytes]) // Вихідний. Зашифровані дані 
								// у вигляді масиву байт (записується 
								// за нулевим індексом)

	EUEnvelopDataToRecipientsWithDynamicKey
	// Зашифрування даних одночасно на декількох одержувачів за допомоги 
	// динамічного ключа протоколу розподілу ключів відправника. Дані 
	// зашифровуються з використанням ключа ГОСТ-28147, після чого ключ 
	// зашифровується направлено для кожного з абонентів з використанням динамічно 
	// згенерованого ключа протоколу розподілу ключів відправника.
	def EnvelopDataToRecipientsWithDynamicKey (
		dwRecipientCerts:		list[bytes],// Вхідний. Список сертифікатів
								// одержувачів у вигліді масиву байт
		bSignData:			Boolean,	// Вхідний. Признак необхідності 
								// додатково підписувати дані
		bAppendCert:		Boolean,	// Вхідний. Включати сертифікат
								// підписувача у підписані дані
		pbData:			bytes,	// Вхідний. Дані для зашифрування у 
								// вигляді масиву байт
		dwDataLength:		long,		// Вхідний. Розмір даних у вигляді
								// масиву байт
		ppszEnvelopedData:	list[bytes], // Вихідний. Зашифровані дані 
								// у вигляді BASE64-строки 
								// (записується за нулевим індексом).
								// Якщо параметр дорівнює None, 
								// зашифровані дані повертаються
								// у вигляді масиву байт
		ppbEnvelopedData:		list[bytes]) // Вихідний. Зашифровані дані 
								// у вигляді масиву байт (записується 
								// за нулевим індексом)

	EUEnvelopFileExWithDynamicKey
	// Зашифрування файла одночасно на декількох одержувачів за допомоги 
	// динамічного ключа протоколу розподілу ключів відправника. Файл 
	// зашифровується з використанням ключа ГОСТ-28147, після чого ключ 
	// зашифровується направлено для кожного з абонентів з використанням динамічно 
	// згенерованого ключа протоколу розподілу ключів відправника.
	def EnvelopFileExWithDynamicKey (
		pszRecipientCertIssuers: list[unicode], // Вхідний. Реквізити 
								// ЦСК сертифікатів одержувачів.
// Якщо кількість 
								// реквізитів ЦСК менша за кількість 
								// серійних номерів сертифікатів 
								// одержувачів останній реквізит ЦСК 
								// в рядку буде використано для 
								// серійних номерів, що лишилися
		pszRecipientCertSerials: list[unicode], // Вхідний. Серійні 
								// номера сертифікатів одержувачів
		bSignData:			Boolean,	// Вхідний. Признак необхідності 
								// додатково підписувати дані
		bAppendCert:		Boolean,	// Вхідний. Включати сертифікат
								// підписувача у підписані дані
		pszFileName:		str,		// Вхідний. Ім’я файлу з даними
		pszEnvelopedFileName:	str)		// Вхідний. Ім’я файлу 
								// в який необхідно записати 
								// зашифровані дані

	EUEnvelopFileToRecipientsWithDynamicKey
	// Зашифрування файла одночасно на декількох одержувачів за допомоги 
	// динамічного ключа протоколу розподілу ключів відправника. Файл 
	// зашифровується з використанням ключа ГОСТ-28147, після чого ключ 
	// зашифровується направлено для кожного з абонентів з використанням динамічно 
	// згенерованого ключа протоколу розподілу ключів відправника.
	def EnvelopFileToRecipientsWithDynamicKey (
		dwRecipientCerts:		list[bytes],// Вхідний. Список сертифікатів
								// одержувачів у вигліді масиву байт
		bSignData:			Boolean,	// Вхідний. Признак необхідності 
								// додатково підписувати дані
		bAppendCert:		Boolean,	// Вхідний. Включати сертифікат
								// підписувача у підписані дані
		pszFileName:		str,		// Вхідний. Ім’я файлу з даними
		pszEnvelopedFileName:	str)		// Вхідний. Ім’я файлу 
								// в який необхідно записати 
								// зашифровані дані

	EUGetSenderInfo
	// Отримання розширеної інформації про відправника зашифрованих даних
	def GetSenderInfo (
		pszEnvelopedData:		bytes,	// Вхідний. Зашифровані дані у
								// вигляді BASE64-строки. Якщо 
								// параметр дорівнює None, 
								// зашифровані дані передаються у
								// вигляді масиву байт
		pbEnvelopedData:		bytes,	// Вхідний. Зашифровані дані у 
								// вигляді масиву байт 
		dwEnvelopedDataLength:	long,		// Вхідний. Розмір 
								// зашифрованих даних у вигляді 
								// масиву байт
		pbRecipientCert:		bytes,	// Вхідний. Сертифікат одержувача 
// у вигляді масиву байт
		dwRecipientCertLength:	long,		// Вхідний. Довжина 
								// сертифіката одержувача 
// у вигляді масиву байт
		pbDynamicKey:	list[Boolean],	// Вихідний. Признак використання 
								// динамічного ключа відправника при 
								// зашифруванні. Сертифікат та 
								// інформація про відправника 
								// відсутні
ppInfo:		EU_CERT_INFO_EX,	// Вихідний. Інформація про 
								// сертифікат відправника. (пам’ять 
								// виділяється автоматично)
		ppbCertificate:	list[bytes])	// Вихідний. Сертифікат відправника
								// у вигляді масиву байт 
								// (записується за нулевим індексом)

	EUGetFileSenderInfo
	// Отримання розширеної інформації про відправника зашифрованих даних для файлу
	def GetFileSenderInfo (
		pszEnvelopedFileName:	str,		// Вхідний. Ім’я файлу з
								// зашифрованими даними
		pbRecipientCert:		bytes,	// Вхідний. Сертифікат одержувача 
// у вигляді масиву байт
		dwRecipientCertLength:	long,		// Вхідний. Довжина 
								// сертифіката одержувача 
// у вигляді масиву байт
		pbDynamicKey:	list[Boolean],	// Вихідний. Признак використання 
								// динамічного ключа відправника при 
								// зашифруванні. Сертифікат та 
								// інформація про відправника 
								// відсутні
ppInfo:		EU_CERT_INFO_EX,	// Вихідний. Інформація про 
								// сертифікат відправника. (пам’ять 
								// виділяється автоматично)
		ppbCertificate:	list[bytes])	// Вихідний. Сертифікат відправника
								// у вигляді масиву байт 
								// (записується за нулевим індексом)

	EUGetRecipientsCount
	// Отримання кількості отримувачів зашифрованих даних
	def GetRecipientsCount (
		pszEnvelopedData:		bytes,	// Вхідний. Зашифровані дані у
								// вигляді BASE64-строки. Якщо 
								// параметр дорівнює None, 
								// зашифровані дані передаються у
								// вигляді масиву байт
		pbEnvelopedData:		bytes,	// Вхідний. Зашифровані дані у 
								// вигляді масиву байт 
		dwEnvelopedDataLength:	long,		// Вхідний. Розмір 
								// зашифрованих даних у вигляді 
								// масиву байт
		pdwCount:			list[long]);// Вихідний. Кількість отримувачів
								// зашифрованих даних

	EUGetFileRecipientsCount
	// Отримання кількості отримувачів зашифрованих даних для файлу
	def GetFileRecipientsCount (
		pszEnvelopedFileName:	str,		// Вхідний. Ім’я файлу з
								// зашифрованими даними
		pdwCount:			list[long]);// Вихідний. Кількість отримувачів
								// зашифрованих даних

	EUGetRecipientInfo
	// Отримання інформації про отримувача зашифрованих даних
	// Якщо в pdwRecipientInfoType[0] повертається константа
	// EU_RECIPIENT_INFO_TYPE_ISSUER_SERIAL, то інформація повертається тільки в 
	// ppszRecipientIssuer та ppszRecipientSerial, інші значення дорівнюють None;
	// EU_RECIPIENT_INFO_TYPE_KEY_ID, то інформація повертається тільки в 
	// ppszRecipientPublicKeyID, інші значення дорівнюють None
	def GetRecipientInfo (
		dwRecipientIndex:		long,		// Вхідний. Індекс отримувача
								// зашифрованих даних
		pszEnvelopedData:		bytes,	// Вхідний. Зашифровані дані у
								// вигляді BASE64-строки. Якщо 
								// параметр дорівнює None, 
								// зашифровані дані передаються у
								// вигляді масиву байт
		pbEnvelopedData:		bytes,	// Вхідний. Зашифровані дані у 
								// вигляді масиву байт 
		dwEnvelopedDataLength:	long,		// Вхідний. Розмір 
								// зашифрованих даних у вигляді 
								// масиву байт
		pdwRecipientInfoType:	list[long]);// Вихідний. Тип інформації
								// про отримувача, що міститься в 
								// зашифрованих даних
		ppszRecipientIssuer:	list[unicode], // Вихідний. Реквізити ЦСК, 
								// що видав сертифікат, пам’ять 
								// виділяється автоматично
		ppszRecipientSerial:	list[unicode], // Вихідний. Реєстраційний 
								// номер сертифіката, пам’ять 
								// виділяється автоматично
		ppszRecipientPublicKeyID:list[unicode], // Вихідний.
								// Ідентифікатор відкритого 
								// ключа отримувача, пам’ять 
								// виділяється автоматично

	EUGetFileRecipientInfo
	// Отримання інформації про отримувача зашифрованих даних для файлу
	// Якщо в pdwRecipientInfoType[0] повертається константа
	// EU_RECIPIENT_INFO_TYPE_ISSUER_SERIAL, то інформація повертається тільки в 
	// ppszRecipientIssuer та ppszRecipientSerial, інші значення дорівнюють None;
	// EU_RECIPIENT_INFO_TYPE_KEY_ID, то інформація повертається тільки в 
	// ppszRecipientPublicKeyID, інші значення дорівнюють None
	def GetFileRecipientInfo (
		dwRecipientIndex:		long,		// Вхідний. Індекс отримувача
								// зашифрованих даних
		pszEnvelopedFileName:	str,		// Вхідний. Ім’я файлу з
								// зашифрованими даними
		pdwRecipientInfoType:	list[long]);// Вихідний. Тип інформації
								// про отримувача, що міститься в 
								// зашифрованих даних
		ppszRecipientIssuer:	list[unicode], // Вихідний. Реквізити ЦСК, 
								// що видав сертифікат, пам’ять 
								// виділяється автоматично
		ppszRecipientSerial:	list[unicode], // Вихідний. Реєстраційний 
								// номер сертифіката, пам’ять 
								// виділяється автоматично
		ppszRecipientPublicKeyID:list[unicode], // Вихідний.
								// Ідентифікатор відкритого 
								// ключа отримувача, пам’ять 
								// виділяється автоматично

І.5.8 Функції роботи з сесією
	EUClientSessionCreateStep1
	// Створення сесії користувачем (Крок 1)
	def ClientSessionCreateStep1 (
		dwExpireTime:	long,			// Вхідний. Час зберігання стану 
								// сесії, с.
		ppvClientSession	list[object],	// Вихідний. Інформація про
								// сесію (записується за нулевим
								// індексом)
		ppbClientData:	list[bytes])	// Вихідний. Інформація про 
								// користувача для серверу у вигляді
								// масиву байт (записується за
								// нулевим індексом)

	EUServerSessionCreateStep1
	// Створення сесії сервером (Крок 1)
	def ServerSessionCreateStep1 (
		dwExpireTime:		long,		// Вхідний. Час зберігання стану 
								// сесії, с.
		pbClientData:		bytes,		// Вхідний. Інформація про 
								// користувача для серверу у вигляді
								// масиву байт
		dwClientDataLength:	long,		// Вхідний. Розмір інформації 
								// про користувача для серверу у 
								// вигляді масиву байт
		ppvServerSession	list[object],	// Вихідний. Інформація про 
								// сесію (записується за нулевим
								// індексом)
		ppbServerData:	list[bytes])	// Вихідний. Інформація про 
								// сервер для користувача у вигляді
								// масиву байт (записується за
								// нулевим індексом)

	EUClientSessionCreateStep2
	// Створення сесії користувачем (Крок 2)
	def ClientSessionCreateStep2 (
		pvClientSession:		object,	// Вхідний. Інформація про сесію
		pbServerData:		bytes,	// Вхідний. Інформація про 
								// сервер для користувача у вигляді
								// масиву байт
		dwServerDataLength:	long,		// Вхідний. Розмір 
								// інформації про сервер для 
								// користувача у вигляді масиву байт
		ppbClientData:		list[bytes])// Вихідний. Інформація про 
								// користувача для серверу у вигляді
								// масиву байт (записується за
								// нулевим індексом)

	EUServerSessionCreateStep2
	// Створення сесії сервером (Крок 2)
	def ServerSessionCreateStep2 (
		pvServerSession:		object,	// Вхідний. Інформація про сесію
		pbClientData:		bytes,	// Вхідний. Інформація про 
								// користувача для серверу у вигляді
								// масиву байт
		dwClientDataLength:	long)		// Вхідний. Розмір інформації 
								// про користувача для серверу у 
								// вигляді масиву байт

	EUClientDynamicKeySessionCreate
	// Створення сесії користувачем з використанням динамічного ключа
	def ClientDynamicKeySessionCreate (
		dwExpireTime:		long,		// Вхідний. Час зберігання стану 
								// сесії, с.
		pszServerCertIssuer:	str,		// Вхідний. Реквізити ЦСК
								// сертифіката серверІ. Якщо NULL,
								// сертифікат передається у вигляді
								// масиву байт
		pszServerCertSerial:	str,		// Вхідний. Серійний номер
								// сертифіката серверІ. Якщо NULL,
								// сертифікат передається у вигляді
								// масиву байт
		pbServerCert:		bytes,	// Вхідний. Сертифікат сервера у 
								// вигляді масиву байт
		dwServerCertLength:	long,		// Вхідний. Розмір 
								// сертифіката сервера у вигляді
								// масиву байт
		ppvClientSession:	list[object],	// Вихідний. Інформація про
								// сесію (записується за нулевим
								// індексом)
		ppbClientData:	list[bytes])	// Вихідний. Інформація про 
								// користувача для серверу у вигляді
								// масиву байт (записується за
								// нулевим індексом)

	EUServerDynamicKeySessionCreate
	// Створення сесії сервером, з використанням динамічного ключа користувача
	def ServerDynamicKeySessionCreate (
		dwExpireTime:		long,		// Вхідний. Час зберігання стану 
								// сесії, с.
		pbClientData:		bytes,	// Вхідний. Інформація про 
								// користувача для серверу у вигляді
								// масиву байт
		dwClientDataLength:	long,		// Вхідний. Розмір інформації 
								// про користувача для серверу у 
								// вигляді масиву байт
		ppvServerSession:		list[object])// Вихідний. Інформація про 
								// сесію (записується за нулевим
								// індексом)

	EUSessionDestroy
	// Знищення інформації про сесію
	def SessionDestroy (
		pvSession:			object)	// Вхідний інформація про сесію

	EUSessionGetPeerCertificateInfo
	// Отримати інформацію про сертифікат взаємодіючої сторони
	def SessionGetPeerCertificateInfo (
		pvSession:			object,	// Вхідний. Інформація про сесію
		pInfo:		EU_CERT_INFO)	// Вихідний. Записується інформація
								// про сертифікат взаємодіючої
								// сторони

	EUSessionCheckCertificates
	// Перевірки сертифікатів взаємодіючих сторін під час сесії
	def SessionCheckCertificates (
		pvSession:			object)	// Вхідний інформація про сесію

	EUSessionIsInitialized
	// Визначення стану сесії. Повертає TRUE, якщо сесію ініціалізовано, інакше - 
	// FALSE
	def SessionIsInitialized (
		pvSession:			object	// Вхідний інформація про сесію
	)-> Boolean


	EUSessionSave, EUSessionLoad
		// Збереження сесії
	def SessionSave (
		pvSession:			object,	// Вхідний інформація про сесію
		ppbSessionData:		list[bytes])// Вихідний. Інформація про 
								// сесію у вигляді масиву байт про 
								// (записується за нулевим індексом)
	// Завантаження сесії
	def SessionLoad (
		pbSessionData:		bytes,	// Вхідний. Інформація про сесію
								// у вигляді масиву байт.
		dwSessionDataLength:	long,		// Вхідний. Розмір 
								// інформації про сесію у вигляді 
								// масиву байт
		ppvSession:		list[object])	// Вихідний. Інформація про сесію
								// (записується за нулевим індексом)

	EUSessionEncrypt
	// Зашифрування даних з маркером самосинхронізації за допомогою ключа сесії.
	def SessionEncrypt (
		pvSession:			object,	// Вхідний інформація про сесію
		pbData:			bytes,	// Вхідний. Дані для зашифрування
								// у вигляді масиву байт.
		dwDataLength:		long,		// Вхідний. Розмір даних для 
								// зашифрування у вигляді масиву
								// байт.
		ppbEncryptedData:		list[bytes])// Вихідний. Зашифровані дані у 
								// вигляді масиву байт (записується
								// за нулевим індексом)

	EUSessionDecrypt
	// Розшифрування даних з маркером самосинхронізації за допомогою ключа сесії.
	def SessionDecrypt
		pvSession:			object,	// Вхідний інформація про сесію
		pbEncryptedData:		bytes,		// Вхідний. Вихідний. Дані для 
								// розшифрування у вигляді масиву
								// байт.
		dwEncryptedDataLength:	long,		// Вхідний. Розмір даних 
								// для розшифрування у вигляді масиву 
								// байт
		ppbData:			list[bytes])// Вихідний. Розшифровані дані у 
								// вигляді масиву байт (записується
								// за нулевим індексом)

І.5.9 Функції роботи з контекстом бібліотеки

	EUCtxCreate
	// Створення контексту бібліотеки
	def CtxCreate (
		ppvContext:		list[object])	// Вихідний. Показчик на контекст 
								// бібліотеки (записується за нулевим
								// індексом)

	EUCtxFree
	// Знищення контексту бібліотеки
	def CtxFree (
		pvContext:			object)	// Вхідний. Показчик на контекст 
								// бібліотеки

	EUCtxCreateEmptySignFile
	// Створення порожнього підпису для файла (Примітка: Розмір файла не обмежений) 
	def CtxCreateEmptySignFile (
		pvContext:			object,	// Вхідний. Показчик на контекст 
								// бібліотеки
		dwSignAlgo:			long,		// Вхідний. Алгоритм підпису
		pszFileName:		str,		// Вхідний. Ім’я файлу з даними, 
								// (якщо підпис зовнішній 
								// pszFileName = None)
		pbCertificate:		bytes,	// Вхідний. Сертифікат підписувача.
		dwCertificateLength:	long,		// Вхідний. Розмір
								// сертифіката підписувача.
		pszFileNameWithSign:	str)		// Вхідний. Ім’я файлу, в 
								// який необхідно записати порожній
								// підпис

	EUCtxAppendSignerFile
	// Додавання інформації про підписувача до підпису для файла (Примітка: Розмір 
	// файла не обмежений) 
	def CtxAppendSignerFile (
		pvContext:			object,	// Вхідний. Показчик на контекст 
								// бібліотеки
		dwSignAlgo:			long,		// Вхідний. Алгоритм підпису, повинен
								// відповідати алгоритму попереднього 
								// підпису
		pbSigner:			bytes,	// Вхідний. Інформація про 
								// підписувача у вигляді масиву байт
		dwSignerLength:		long,		// Вхідний. Розмір інформації 
								// про підписувача у вигляді масиву
								// байт
		pbCertificate:		bytes,	// Вхідний. Сертифікат підписувача.
								// Якщо параметр дорівнює None
								// сертифікат до підпису не додається
		dwCertificateLength:	long,		// Вхідний. Розмір
								// сертифіката підписувача.
		pszFileNameWithPreviousSign:	str,	// Вхідний. Ім’я 
								// файлу з попереднім підписом
								// (якщо тип підпису зовнішній)
								// або підписаними даними 
								// (якщо тип підпису внутрішній)
		pszFileNameWithSign:	str)		// Вхідний. Ім’я файлу, в 
								// який необхідно записати 
								// підпис (якщо тип підпису 
								// зовнішній) або підписані дані 
								// (якщо тип підпису внутрішній)

	EUCtxIsNamedPrivateKeyExists
	// Визначає чи є особистий ключ на носії, що підтримує декілька ключів
	def CtxIsNamedPrivateKeyExists (
		pvContext:			object,	// Вхідний. Показчик на контекст 
								// бібліотеки
		pKeyMedia:		EU_KEY_MEDIA,	// Вхідний. Параметри носія 
								// особистого ключа. Якщо None носій 
								// обирається за допомогою 
								// графічного інтерфейсу бібліотеки
		pszNamedPrivateKeyLabel:	str,	// Вхідний. 
								// Ідентифікатор ос. ключа
		pszNamedPrivateKeyPassword:	str,	// Вхідний. Пароль 
								// від ос. ключа
		pbExists:		list[Boolean])	// Вихідний. Признак наявності 
								// особистого ключа на носії 
								// (записується за нулевим індексом)

	EUCtxGenerateNamedPrivateKey
	// Генерація особистого ключа на пристрої, що підтримує декілька ключів. 
	// Можливі 2 режими роботи функції:
	// 1) Графічний. Параметри носія з особистим ключем не передаються(pKeyMedia = 
	// None), носій обирається за допомогою графічного інтерфейсу бібліотеки. 
	// Графічний інтерфейс бібліотеки підтримується тільки ОС Windows розрядністю 
	// 32 біта.
	// 2) Не графічний. Передаються параметри носія з особистим ключем
	def CtxGenerateNamedPrivateKey (
		pvContext:			object,	// Вхідний. Показчик на контекст
								// бібліотеки
		pKeyMedia:		EU_KEY_MEDIA,	// Вхідний. Параметри носія 
								// особистого ключа. Якщо None носій 
								// обирається за допомогою
								// графічного інтерфейсу бібліотеки 
		pszNamedPrivateKeyLabel:	str,	// Вхідний. 
								// Ідентифікатор ос. ключа
		pszNamedPrivateKeyPassword:	str,	// Вхідний. Пароль 
								// від ос. ключа
		dwUAKeysType:			long,	// Вхідний. Тип ключа для державних 
								// криптографічних алгоритмів та 									// протоколів
		dwUADSKeysSpec:			long, // Вхідний. Параметри ключа ЕЦП 									// для державних криптографічних
								// алгоритмів та протоколів 
		dwUAKEPKeysSpec:			long, // Вхідний. Параметри ключа 
								// протоколу розподілу ключів
								// для державних криптографічних
								// алгоритмів та протоколів.
		pszUAParamsPath:			str,	// Вхідний. Каталог чи носій з 
								// параметрами ЕЦП та протоколу 
								// розподілу ключів для державних 
								// криптографічних алгоритмів та 
								// протоколів 
		dwInternationalKeysType:	long, // Вхідний. Тип ключа 
								// для міжнародних криптографічних
								// алгоритмів та протоколів
		dwInternationalKeysSpec:	long, // Вхідний. Параметри 
								// ключа для міжнародних 
								// криптографічних алгоритмів та 
								// протоколів
		pszInternationalParamsPath:	str,	// Вхідний. Каталог 
								// чи носій з параметрами для 
								// міжнародних криптографічних
								// алгоритмів та протоколів
		ppbUARequest:		list[bytes],// Вихідний. Запит на сертифікат у 
								// вигляді масиву байт для державних 
								// криптографічних алгоритмів та 
								// протоколів (записується
								// за нулевим індексом). Якщо 
								// генерується ключ для міжнародних 
								// криптографічних алгоритмів та 
								// протоколів повинен дорівнювати
								// None.
		pszUAReqFileName:		list[str],	// Вихідний. Ім’я файлу за 
								// замувчунням для запиту на 
								// сертифікат для державних 
								// криптографічних алгоритмів та 
								// протоколів(записується
								// за нулевим індексом)
		ppbUAKEPRequest:		list[bytes],// Вихідний. Запит на 
								// сертифікат особистого ключа 
								// протоколу розподілу ключів у 
								// вигляді масиву байт для державних 
								// криптографічних алгоритмів та 
								// протоколів (записується
								// за нулевим індексом). Якщо 
								// генерується ключ для міжнародних 
								// криптографічних алгоритмів та 
								// протоколів або якщо не потрібен 
								// окремий ключ для протоколу
								// розподілу ключів повинен 
								// дорівнювати None
		pszUAKEPReqFileName:	list[str],	// Вихідний. Ім’я файлу за 
								// замувчунням для запиту на 
								// сертифікат особистого ключа 
								// протоколу розподілу ключів для 
								// державних криптографічних 
								// алгоритмів та протоколів
								// (записується за нулевим індексом)
		ppbInternationalRequest: list[bytes],// Вихідний. Запит на 
								// сертифікат особистого ключа у
								// вигляді масиву байт для 
								// міжнародних криптографічних 
								// алгоритмів та протоколів
								// (записується за нулевим індексом).
		pszInternationalReqFileName: list[str]) // Вихідний. 
								// Ім’я файлу за замувчунням для 
								// запиту на сертифікат особистого 
								// ключа для міжнародних 
								// криптографічних алгоритмів та
								// протоколів
								// (записується за нулевим індексом)

	EUCtxReadNamedPrivateKey
	// Зчитування особистого ключа (див. дод. Е.3) до контексту з пристрою, що	// підтримує декілька ключів. Контекст ключа асоційовано з контекстом 
	// бібліотеки pvContext
	def CtxReadNamedPrivateKey (
		pvContext:			object,	// Вхідний. Показчик на контекст
								// бібліотеки
		pKeyMedia:		EU_KEY_MEDIA,	// Вхідний. Параметри носія 
								// особистого ключа
		pszNamedPrivateKeyLabel:	str,	// Вхідний. 
								// Ідентифікатор ос. ключа
		pszNamedPrivateKeyPassword:	str,	// Вхідний. Пароль 
								// від ос. ключа
		ppvPrivKeyContext:	list[object],// Вихідний. Показчик на контекст 
								// ключа (записується за нулевим
								// індексом)
		pInfo:	EU_CERT_OWNER_INFO)	// Вихідний. Якщо не None записується
								// інформація про 
								// сертифікат власника

	EUCtxDestroyNamedPrivateKey
	// Знищення особистого ключа на носії, що підтримує декілька ключів
	def CtxDestroyNamedPrivateKey (
		pvContext:			object,	// Вхідний. Показчик на контекст
								// бібліотеки
		pKeyMedia:		EU_KEY_MEDIA,	// Вхідний. Параметри носія 
								// особистого ключа. Якщо None носій 
								// обирається за допомогою
								// графічного інтерфейсу бібліотеки
		pszNamedPrivateKeyLabel:	str,	// Вхідний. 
								// Ідентифікатор ос. ключа
		pszNamedPrivateKeyPassword:	str)	// Вхідний. Пароль 
								// від ос. ключа

	EUCtxChangeNamedPrivateKeyPassword
	// Зміна паролю захисту особистого ключа на носії, що підтримує декілька ключів
	def CtxChangeNamedPrivateKeyPassword (
		pvContext:			object,	// Вхідний. Показчик на контекст
								// бібліотеки
		pKeyMedia:		EU_KEY_MEDIA,	// Вхідний. Параметри носія 
								// особистого ключа. Якщо None носій 
								// обирається за допомогою
								// графічного інтерфейсу бібліотеки
		pszNamedPrivateKeyLabel:	str,	// Вхідний. 
								// Ідентифікатор ос. ключа
		pszNamedPrivateKeyPassword:	str,	// Вхідний. Пароль 
								// від ос. ключа
		pszNamedPrivateKeyNewPassword: str)	// Вхідний. Новий пароль 
								// від ос. ключа

	EUCtxSignHashValue
	// Формування підпису геша. (Примітка: При формуванні геш значення необхідно 
	// використовувати сертифікат підписувача)
	def CtxSignHashValue (
		pvPrivateKeyContext:	object,	// Вхідний. Показчик на контекст
								// особистого ключа
		dwSignAlgo:			long,		// Вхідний. Алгоритм підпису
		pbHash:			bytes,	// Вхідний. Геш у вигляді масиву байт
		dwHashLength:		long,		// Вхідний. Розмір гешу
		bAppendCert:		Boolean,	// Вхідний. Включати сертифікат
								// підписувача у підписані дані
		ppbSign:		list[bytes])	// Вихідний. Підпис у вигляді масиву 
								// байт (записується
								// за нулевим індексом)

	EUCtxSignData
	// Формування електронного цифрового підпису (ЕЦП)
	def CtxSignData (
		pvPrivateKeyContext:	object,	// Вхідний. Показчик на контекст
								// особистого ключа
		dwSignAlgo:			long,		// Вхідний. Алгоритм підпису
		pbData:			bytes,	// Вхідний. Дані для підпису
		dwDataLength:		long,		// Вхідний. Розмір даних для підпису
		bExternal:			Boolean,	// Вхідний. Якщо bExternal = True, 
								// формується зовнішній ЕЦП (дані, що 
								// підписуються знаходяться окремо 
								// від ЕЦП), інакше – внутрішній ЕЦП 
								// (дані, що підписуються знаходяться 
								// в ЕЦП)
		bAppendCert:		Boolean,	// Вхідний. Включати сертифікат
								// підписувача у підписані дані
		ppbSign:		list[bytes])	// Вихідний. Підпис у вигляді масиву 
								// байт (записується
								// за нулевим індексом)

	EUCtxFreePrivateKey
	// Звільнення контекста з ключем
	def CtxFreePrivateKey (
		pvPrivKeyContext:		object)	// Вхідний. Показчик на контекст 
								// ключа

								// особистого ключа на носії 
								// (записується за нулевим індексом)

	EUCtxGenerateNamedPrivateKeyEx
	// Генерація особистого ключа з данними для запиту на сертифікацію на пристрої, 	// що підтримує декілька ключів. Можливі 2 режими роботи функції:
	// 1) Графічний. Параметри носія з особистим ключем не передаються(pKeyMedia = 
	// None), носій обирається за допомогою графічного інтерфейсу бібліотеки. 
	// Графічний інтерфейс бібліотеки підтримується тільки ОС Windows розрядністю 
	// 32 біта.
	// 2) Не графічний. Передаються параметри носія з особистим ключем
	def CtxGenerateNamedPrivateKey (
		pvContext:			object,	// Вхідний. Показчик на контекст
								// бібліотеки
		pKeyMedia:		EU_KEY_MEDIA,	// Вхідний. Параметри носія 
								// особистого ключа. Якщо None носій 
								// обирається за допомогою
								// графічного інтерфейсу бібліотеки 
		pszNamedPrivateKeyLabel:	str,	// Вхідний. 
								// Ідентифікатор ос. ключа
		pszNamedPrivateKeyPassword:	str,	// Вхідний. Пароль 
								// від ос. ключа
		dwUAKeysType:			long,	// Вхідний. Тип ключа для державних 
								// криптографічних алгоритмів та 									// протоколів
		dwUADSKeysSpec:			long, // Вхідний. Параметри ключа ЕЦП 									// для державних криптографічних
								// алгоритмів та протоколів 
		dwUAKEPKeysSpec:			long, // Вхідний. Параметри ключа 
								// протоколу розподілу ключів
								// для державних криптографічних
								// алгоритмів та протоколів.
		pszUAParamsPath:			str,	// Вхідний. Каталог чи носій з 
								// параметрами ЕЦП та протоколу 
								// розподілу ключів для державних 
								// криптографічних алгоритмів та 
								// протоколів 
		dwInternationalKeysType:	long, // Вхідний. Тип ключа 
								// для міжнародних криптографічних
								// алгоритмів та протоколів
		dwInternationalKeysSpec:	long, // Вхідний. Параметри 
								// ключа для міжнародних 
								// криптографічних алгоритмів та 
								// протоколів
		pszInternationalParamsPath:	str,	// Вхідний. Каталог 
								// чи носій з параметрами для 
								// міжнародних криптографічних
								// алгоритмів та протоколів
		pUserInfo:		EU_USER_INFO,	// Вхідний. Інформація користувача, 
								// що додається до запиту на
								// сертифікацію. Якщо pUserInfo = 
								// None інформація в запит не 
								// додається
		pszExtKeyUsages:			str,	// Вхідний. Уточнене призначення 
								// ключів. Якщо pszExtKeyUsages = 
								// None або pUserInfo = None
								// інформація в запит не додається
		ppbUARequest:		list[bytes],// Вихідний. Запит на сертифікат у 
								// вигляді масиву байт для державних 
								// криптографічних алгоритмів та 
								// протоколів (записується
								// за нулевим індексом). Якщо 
								// генерується ключ для міжнародних 
								// криптографічних алгоритмів та 
								// протоколів повинен дорівнювати
								// None.
		pszUAReqFileName:		list[str],	// Вихідний. Ім’я файлу за 
								// замувчунням для запиту на 
								// сертифікат для державних 
								// криптографічних алгоритмів та 
								// протоколів(записується
								// за нулевим індексом)
		ppbUAKEPRequest:		list[bytes],// Вихідний. Запит на 
								// сертифікат особистого ключа 
								// протоколу розподілу ключів у 
								// вигляді масиву байт для державних 
								// криптографічних алгоритмів та 
								// протоколів (записується
								// за нулевим індексом). Якщо 
								// генерується ключ для міжнародних 
								// криптографічних алгоритмів та 
								// протоколів або якщо не потрібен 
								// окремий ключ для протоколу
								// розподілу ключів повинен 
								// дорівнювати None
		pszUAKEPReqFileName:	list[str],	// Вихідний. Ім’я файлу за 
								// замувчунням для запиту на 
								// сертифікат особистого ключа 
								// протоколу розподілу ключів для 
								// державних криптографічних 
								// алгоритмів та протоколів
								// (записується за нулевим індексом)
		ppbInternationalRequest: list[bytes],// Вихідний. Запит на 
								// сертифікат особистого ключа у
								// вигляді масиву байт для 
								// міжнародних криптографічних 
								// алгоритмів та протоколів
								// (записується за нулевим індексом).
		pszInternationalReqFileName: list[str]) // Вихідний. 
								// Ім’я файлу за замувчунням для 
								// запиту на сертифікат особистого 
								// ключа для міжнародних 
								// криптографічних алгоритмів та
								// протоколів
								// (записується за нулевим індексом)

	EUCtxReadPrivateKey
	// Зчитування особистого ключа (див. дод. Е.3) до контексту, контекст ключа
	// асоційовано з контекстом бібліотеки pvContext
	def CtxReadPrivateKey (
		pvContext:			object,	// Вхідний. Показчик на контекст
								// бібліотеки
		pKeyMedia:		EU_KEY_MEDIA,	// Вхідний. Параметри носія 
								// особистого ключа
		ppvPrivKeyContext:	list[object],// Вихідний. Показчик на контекст 
								// ключа (записується за нулевим
								// індексом)
		pInfo:	EU_CERT_OWNER_INFO)	// Вихідний. Якщо не None записується
								// інформація про 
								// сертифікат власника

	EUCtxReadPrivateKeyBinary
	// Зчитування особистого ключа у вигляді масиву байт до контексту, контекст 
	// ключа асоційовано з контекстом бібліотеки pvContext
	def CtxReadPrivateKeyBinary (
		pvContext:			object,	// Вхідний. Показчик на контекст
								// бібліотеки
		pbPrivateKey:		bytes,	// Вхідний. Особистий ключ у вигляді 
								// масиву байт
		dwPrivateKeyLength:	long,		// Вхідний. Довжина											// особистого ключа у вигляді масиву
								// байт
		pszPassword:		str,		// Вхідний. Пароль доступу до 
								// особистого ключа
		ppvPrivKeyContext:	list[object],// Вихідний. Показчик на контекст 
								// ключа (записується за нулевим
								// індексом)
		pInfo:	EU_CERT_OWNER_INFO)	// Вихідний. Якщо не None записується
								// інформація про 
								// сертифікат власника

	EUCtxMakeDeviceCertificate
	// Формування сертифікату для пристрою з використанням контексту зчитаного 
	// ос. ключа та діючого сертифікату ос. ключа. Функція потребує доступу до 
	// сервера CMP ЦСК та підтримки автоматичного формування сертифікатів для 
	// пристроїва серером CMP ЦСК
	def CtxMakeDeviceCertificate (
		pvPrivateKeyContext:	object,	// Вхідний. Показчик на контекст
								// особистого ключа
		pszDeviceName:		str,		// Вхідний. Ім`я пристрою
		pbUARequest:		bytes,	// Вхідний. Запит на сертифікат у 
								// вигляді масиву байт для державних 
								// криптографічних алгоритмів та 
								// протоколів. Якщо None сертифікат 
								// не формується
		dwUARequestLength:	long,		// Вхідний. Розмір запиту 
								// на сертифікат особистого ключа 
								// протоколу розподілу ключів у 
								// вигляді масиву байт для державних
								// криптографічних алгоритмів
								// та протоколів
		pbUAKEPRequest:		bytes,	// Вхідний. Запит на 
								// сертифікат особистого ключа 
								// протоколу розподілу ключів у 
								// вигляді масиву байт для державних 
								// криптографічних алгоритмів та 
								// протоколів. Якщо None сертифікат 
								// не формується
		dwUAKEPRequestLength:	long,		// Вхідний. Розмір запиту 
								// на сертифікат особистого ключа 
								// протоколу розподілу ключів у 
								// вигляді масиву байт для державних
								// криптографічних алгоритмів
								// та протоколів
		pbInternationalRequest:	bytes,	// Вхідний. Запит на 
								// сертифікат особистого ключа у
								// вигляді масиву байт для 
								// міжнародних криптографічних 
								// алгоритмів та протоколів. Якщо 
								// None сертифікат не формується
		dwInternationalRequestLength:	long,	// Вхідний. Розмір 
								// запиту на сертифікат особистого 
								// ключа у вигляді масиву байт для
								// міжнародних криптографічних
								// алгоритмів та протоколів
		pbECDSARequest:		bytes,	// Вхідний. Запит на 
								// сертифікат особистого ключа у
								// вигляді масиву байт для 
								// алгоритмів та протоколів ECDSA. 
								// Якщо None сертифікат 
								// не формується
		dwECDSARequestLength:	long,		// Вхідний. Розмір 
								// запиту на сертифікат особистого 
								// ключа у вигляді масиву байт для
								// алгоритмів та протоколів ECDSA
		pszCMPAddress:		str,		// Вхідний. Адреса CMP-сервера ЦСК
		pszCMPPort:			str,		// Вхідний. Порт CMP-сервера ЦСК
		ppbUACertificate:		list[bytes],// Вихідний. Сертифікат у 
								// вигляді масиву байт для державних 
								// криптографічних алгоритмів та 
								// протоколів (записується
								// за нулевим індексом) 
		ppbUAKEPCertificate:	list[bytes],// Вихідний. Сертифікат
								// протоколу розподілу ключів у 
								// вигляді масиву байт для державних 
								// криптографічних алгоритмів та 
								// протоколів (записується
								// за нулевим індексом) 
		ppbInternationalCertificate:list[bytes],// Вихідний. Сертифікат у вигляді 
								// масиву байт для міжнародних 
								// криптографічних  алгоритмів та 
								// протоколів (записується
								// за нулевим індексом) 
		ppbECDSACertificate:	list[bytes])// Вихідний. Сертифікат у вигляді 
								// масиву байт для алгоритмів та 
								// протоколів ECDSA (записується
								// за нулевим індексом)

	EUCtxEnvelopData
	// Зашифрування даних
	def CtxEnvelopData (
		pvPrivateKeyContext:	object,	// Вхідний. Показчик на контекст
								// особистого ключа
		dwRecipientCerts:		list[bytes],// Вхідний. Список сертифікатів
								// одержувачів у вигліді масиву байт
		dwRecipientAppendType:	long,		// Вхідний. Тип інформації
								// про отримувача, що додається до 
								// зашифрованих даних
		bSignData:			Boolean,	// Вхідний. Признак необхідності 
								// додатково підписувати дані
		bAppendCert:		Boolean,	// Вхідний. Включати сертифікат
								// підписувача у підписані дані
		pbData:			bytes,	// Вхідний. Дані для зашифрування у 
								// вигляді масиву байт
		dwDataLength:		long,		// Вхідний. Розмір даних у вигляді
								// масиву байт
		ppbEnvelopedData:		list[bytes])// Вихідний. Зашифровані дані 
								// у вигляді масиву байт (записується 
								// за нулевим індексом)

	EUDevelopData
	// Розшифрування даних з використанням контексту особистого ключа.
	// Якщо передається сертифікат відправника (pbSenderCert) сертифікат 
	// відправника зашифрованих даних не перевіряється у файловому сховищі та не
	// записується до файлового сховища
	def CtxDevelopData (
		pvPrivateKeyContext:	object,	// Вхідний. Показчик на контекст
								// особистого ключа
		pszEnvelopedData:		bytes,	// Вхідний. Зашифровані дані у
								// вигляді BASE64-строки. Якщо 
								// параметр дорівнює None, 
								// зашифровані дані передаються у
								// вигляді масиву байт
		pbEnvelopedData:		bytes,	// Вхідний. Зашифровані дані у 
								// вигляді масиву байт 
		dwEnvelopedDataLength:	long,		// Вхідний. Розмір 
								// зашифрованих даних у вигляді 
								// масиву байт
		pbSenderCert:		bytes,	// Вхідний. Сертифікат відправника
								// у вигляді масиву байт
		dwSenderCertSize:		long,		// Вхідний. Розмір сертифіката 
								// відправника у вигляді масиву байт
		ppbData:			list[bytes],// Вихідний. Розшифровані дані для у 
								// вигляді масиву байт (записується
								// за нулевим індексом)
		pInfo:		EU_ENVELOP_INFO)	// Вихідний. Якщо не None записується
								// інформація про 
								// відправника зашифрованих даних

	EUCtxGetOwnCertificate
	// Отримання інформації про сертифікат особистого ключа
	def CtxGetOwnCertificate (
		pvPrivateKeyContext:	object,	// Вхідний. Показчик на контекст
								// особистого ключа
		dwCertKeyType		long,		// Вхідний. Тип ключа
		dwKeyUsage			long,		// Вхідний. Призначення ключа
		ppInfo:		EU_CERT_INFO_EX,	// Вихідний. Записується детальна
								// інформація про сертифікат
		ppbCertificate:		list[bytes])// Вихідний. Сертифікат у 
								// вигляді масиву байт (записується
								// за нулевим індексом)

І.5.10 Функції роботи з транспортними заголовками

	EUAppendTransportHeader
	// Формування основного транспортого заголовка
	def AppendTransportHeader (
		pszCAType:			str,		// Вхідний. Тип ЦСК (фіксоване 
								// значення - UA1)
		pszFileName:		str,		// Вхідний. Ім'я файлу звіту
		pszClientEMail:		str,		// Вхідний. EMail-адреса 
								// відправника
		pbClientCert:		bytes,	// Вхідний. Сертифікат відправника
		dwClientCertLength:	long,		// Вхідний. Розмір
								// сертифіката відправника
		pbCryptoData:		bytes,	// Вхідний. Криптографічні дані,
								// до яких необхідно додати заголовок
		dwCryptoDataLength:	long,		// Вхідний. Розмір 
								// даних до яких необхідно додати
								// заголовок
		ppbTransportData:		list[bytes])// Вихідний. Транспортний
								// заголовком з даними (записується
								// за нулевим індексом)

	EUParseTransportHeader
	// Отримання інформації з основного транспортого заголовка
	def ParseTransportHeader (
		pbTransportData:		bytes,	// Вхідний. Вміст звіту або 
								// квитанції
		dwTransportDataLength:	long,		// Вхідний. Розмір звіту 
								// або квитанції
		pdwReceiptNumber:		list[long],	// Вихідний. Номер звіту або
								// квитанції
		ppbCryptoData:		list[bytes])// Вихідний. Криптографічні дані

	EUAppendCryptoHeader
	// Формування проміжного транспортого заголовка
	def AppendCryptoHeader (
		pszCAType:			str,		// Вхідний. Тип ЦСК (фіксоване 
								// значення - UA1)
		dwHeaderType:		long,		// Вхідний. Тип заголовку
		pbCryptoData:		bytes,	// Вхідний. Криптографічні дані,
								// до яких необхідно додати заголовок
		dwCryptoDataLength:	long,		// Вхідний. Розмір 
								// даних до яких необхідно додати
								// заголовок
		ppbTransportData:		list[bytes])// Вихідний. Транспортний
								// заголовком (записується
								// за нулевим індексом)

	EUParseCryptoHeader
	// Отримання інформації з проміжного транспортого заголовка
	def ParseCryptoHeader (
		pbTransportData:		bytes,	// Вхідний. Вміст звіту або 
								// квитанції
		dwTransportDataLength:	long,		// Вхідний. Розмір звіту 
								// або квитанції
		pszCAType:			list[str],	// Вихідний. Тип ЦСК
		pdwHeaderType:		list[long],	// Вихідний. Тип криптографічного
								// заголовку
		pdwHeaderSize:		list[long],	// Вихідний. Розмір 
								// криптографічного заголовку
		ppbCryptoData:		list[bytes])// Вихідний. Криптографічні дані

