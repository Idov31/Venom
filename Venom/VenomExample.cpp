#include "pch.h"
#include "Venom.hpp"

void PrintBanner() {
	const char* banner = R""""(

 _   _                            
| | | |                           
| | | | ___ _ __   ___  _ __ ___  
| | | |/ _ \ '_ \ / _ \| '_ ` _ \ 
\ \_/ /  __/ | | | (_) | | | | | |
 \___/ \___|_| |_|\___/|_| |_| |_|
                                  
)"""";
	std::cout << banner << std::endl;
}

int main()
{
	PrintBanner();
	Venom venom = Venom(L"127.0.0.1", 3110);
	char data[14];

	if (!venom.VenomObtainSocket()) {
		std::cerr << "[ - ] Failed to get socket." << std::endl;
		venom.~Venom();
		return -1;
	}
	std::cout << "[ + ] Socket obtained!" << std::endl;

	if (venom.VenomSendData("Hello World!") == SOCKET_ERROR)
		std::cerr << "[ - ] Failed to send data: " << WSAGetLastError() << std::endl;
	else
		std::cout << "[ + ] Data sent!" << std::endl;

	if (venom.VenomReceiveData(data, 14) == SOCKET_ERROR)
		std::cerr << "[ - ] Failed to send data: " << WSAGetLastError() << std::endl;
	else
		std::cout << "[ + ] Data sent!" << std::endl;

	venom.~Venom();
	return 0;
}
