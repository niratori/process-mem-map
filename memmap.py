import ctypes
import psutil
from ctypes import wintypes

# --- PERMISSÕES DO WINDOWS ---
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

def achar_id_do_processo(nome_do_app):
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'].lower() == nome_do_app.lower():
            return proc.info['pid']
    return None

def mapear_memoria(pid):
    # Abrindo o processo com permissão de leitura
    handle = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    
    if not handle:
        print(f"[!] Erro: Não consegui abrir o PID {pid}. Rode como ADMIN!")
        return

    # Estrutura MBI ajustada para 64 bits
    class MEMORY_BASIC_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BaseAddress", ctypes.c_void_p),
            ("AllocationBase", ctypes.c_void_p),
            ("AllocationProtect", wintypes.DWORD),
            ("RegionSize", ctypes.c_size_t),
            ("State", wintypes.DWORD),
            ("Protect", wintypes.DWORD),
            ("Type", wintypes.DWORD),
        ]

    mbi = MEMORY_BASIC_INFORMATION()
    
    # IMPORTANTE: Definimos o endereço inicial como um "Ponteiro Vazio" (void pointer)
    # Isso evita o erro de Overflow no Python 64-bit
    endereco_atual = ctypes.c_void_p(0)

    print(f"\n>>> Mapa de Memória do PID: {pid} <<<")
    print(f"{'Endereço Base':<18} | {'Tamanho (KB)':<12} | {'Permissão'}")
    print("-" * 60)

    # VirtualQueryEx agora recebe o ponteiro corretamente
    while ctypes.windll.kernel32.VirtualQueryEx(handle, endereco_atual, ctypes.byref(mbi), ctypes.sizeof(mbi)):
        
        # MEM_COMMIT (0x1000) = Memória física alocada
        if mbi.State == 0x1000:
            # Simplificando as permissões para o seu estudo:
            # 0x20 e 0x40 são permissões de EXECUÇÃO (onde o código roda)
            pode_executar = mbi.Protect in [0x20, 0x40]
            status = "RWX (Executável)" if pode_executar else "RW (Dados/Stack)"
            
            tamanho_kb = mbi.RegionSize // 1024
            
            # Formatando o endereço para hex de 12 dígitos (Padrão x64)
            addr = mbi.BaseAddress if mbi.BaseAddress else 0
            print(f"0x{addr:012X} | {tamanho_kb:<12} | {status}")

        # Atualizando o endereço para a próxima região
        # A conta precisa ser feita em inteiro e depois convertida de volta para ponteiro
        novo_endereco = (mbi.BaseAddress or 0) + mbi.RegionSize
        endereco_atual = ctypes.c_void_p(novo_endereco)

    ctypes.windll.kernel32.CloseHandle(handle)

# --- TESTE ---
alvo = "notepad.exe" # Abre o bloco de notas antes!
pid = achar_id_do_processo(alvo)

if pid:
    print(f"[+] Alvo: {alvo} | PID: {pid}")
    mapear_memoria(pid)
else:
    print(f"[!] Abre o {alvo} primeiro!")
