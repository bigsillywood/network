#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <tchar.h>
DWORD getpidbyname(const char *name){
    DWORD processid[1024],countprocess,writelen;
    if(!EnumProcesses(processid,sizeof(processid),&writelen)){
        printf("读取进程失败\n");
        return 0;
    };
    countprocess=writelen/sizeof(DWORD);
    printf("获取了%d个进程\n",countprocess);
    TCHAR processNameBuffer[MAX_PATH];
    for(DWORD i=0;i<countprocess;i++){
        HANDLE process=OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processid[i]);
        if(process){
            HMODULE pro;
            DWORD writesize2;
            if(EnumProcessModules(process,&pro,sizeof(pro),&writesize2)){
                GetModuleBaseName(process, pro, processNameBuffer, sizeof(processNameBuffer) / sizeof(TCHAR));
                if (_stricmp(processNameBuffer,name)==0)
                {
                    printf("找到进程名位%s的进程\n",processNameBuffer);
                    CloseHandle(process);
                    return processid[i];
                }
                
            }
        CloseHandle(process);
        }
    }
    printf("未找到指定进程\n");
    return 0;
}
void GetModuleNameByAddress(DWORD processID, uintptr_t lpAddres,char *modulename) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);
    if (hProcess == NULL) {
        _tprintf(TEXT("Failed to open process.\n"));
        return;
    }

    HMODULE hMods[2048];
    DWORD cbNeeded;
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            MODULEINFO modInfo;
            if (GetModuleInformation(hProcess, hMods[i], &modInfo, sizeof(MODULEINFO))) {
                // Check if the given address is within the module's memory range
                uintptr_t base_address=(uintptr_t)modInfo.lpBaseOfDll;
                uintptr_t bound_address=(uintptr_t)modInfo.lpBaseOfDll + (uintptr_t)modInfo.SizeOfImage;
                if (lpAddres >= base_address && lpAddres < bound_address) {
                    char szModName[MAX_PATH];
                    if (GetModuleBaseName(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(TCHAR))) {
                        strcpy(modulename, (char)szModName);
                        _tprintf(TEXT("地址 %p 在: %s模块里\n"), lpAddres, szModName);

                        CloseHandle(hProcess);
                        return;
                    }
                }
            }
        }
    }

    _tprintf(TEXT("没有模块包含此地址\n"));
    CloseHandle(hProcess);
}

void address_compute(DWORD pid,const char* module_name,uintptr_t *offset){
    HANDLE process=OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid);
    if(process){
        HMODULE pro[1024];
        DWORD size2;
        if(EnumProcessModules(process,pro,sizeof(pro),&size2)){
            
            for(unsigned int i=0;i<size2/(sizeof(HMODULE));i++){
                char currentModuleName[MAX_PATH];
                if(GetModuleBaseName(process, pro[i], currentModuleName, sizeof(currentModuleName) / sizeof(TCHAR))){
                    if(_strcmpi(module_name, currentModuleName) == 0){
                        MODULEINFO modInfo;
                        if (GetModuleInformation(process, pro[i], &modInfo, sizeof(MODULEINFO))) {
                            uintptr_t baseAddress = (uintptr_t)modInfo.lpBaseOfDll;
                            printf("基础地址为%p\n",baseAddress);
                            *offset =baseAddress-(*offset);
                            printf("计算地址完成\n");
                            CloseHandle(process);
                            printf("实际地址为%p\n",(void*)*offset);
                            return;
                        }else{
                            printf("模块信息获取失败\n");
                        }
                    }
                    

                }
            }
            printf("没有指定模块\n");
        }else{
            printf("进程模块获取失败\n");
        }
        
    }else{
        printf("进程句柄打开失败\n");
    }
    printf("地址计算失败\n");

    
    CloseHandle(process);

}
void readmem(DWORD Pid,char *buffer_data,uintptr_t address,size_t bufferSize){
    HANDLE process=OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, Pid);
    if(process==NULL){
        DWORD dwError = GetLastError();
        printf("打开句柄失败，错误码: %lu\n", dwError);
        return;
    }else{
        printf("打开句柄成功\n");
        
    }
    size_t read_size;
    if(!ReadProcessMemory(process,(LPCVOID)address,buffer_data,bufferSize,&read_size)){

        MEMORY_BASIC_INFORMATION mbi;
        SIZE_T result = VirtualQueryEx(process, address, &mbi, sizeof(mbi));

        if (result == sizeof(mbi)) {
            printf("BaseAddress: %p\n", mbi.BaseAddress);
            printf("AllocationBase: %p\n", mbi.AllocationBase);
            printf("AllocationProtect: %lu\n", mbi.AllocationProtect);
            printf("RegionSize: %zu\n", mbi.RegionSize);
            printf("State: %lu\n", mbi.State);
            printf("Protect: %lu\n", mbi.Protect);
            printf("Type: %lu\n", mbi.Type);
        } else {
            printf("VirtualQueryEx failed.\n");
        }
        printf("读取内存失败\n");
        printf("读取内存失败, 错误码: %lu\n", GetLastError());
    }else{
        printf("读取内存成功\n");
        printf("读取内容为:\n");
        for (size_t i = 0; i < read_size; ++i) {
            printf("%02X ", (unsigned char)buffer_data[i]);
        }
        printf("\n");
    }
    CloseHandle(process);
}
void writemem(DWORD Pid,char *buffer,uintptr_t address,size_t buffer_size){
    SIZE_T write_size;
    HANDLE process=OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, Pid);
    if(!WriteProcessMemory(process,(LPCVOID)address,buffer,buffer_size,&write_size)){
        printf("写入内存失败\n");
    }else{
        printf("写入内存成功\n");
    }
    CloseHandle(process);
}

int main(void){
    SetConsoleOutputCP(CP_UTF8);
    char processname[MAX_PATH];
    uintptr_t cyber_2077money=0x13674C46C38;
    size_t bufferSize=4;
    char buffer[bufferSize];
    char write_buffer[]={0x3F,0X42,0X0F,0X00};
    char modname[MAX_PATH];
    while(1){
        printf("请输入进程名称:\n");
        scanf("%s",processname);
        DWORD id=getpidbyname(processname);
        printf("进程id为%d\n",id);
        //address_compute(id,"Cyberpunk2077.exe",&cyber_2077money);
        GetModuleNameByAddress(id, cyber_2077money,modname);
        readmem(id,buffer,cyber_2077money,bufferSize);
        //writemem(id,write_buffer,cyber_2077money,bufferSize);
    }
    return 0;
}
