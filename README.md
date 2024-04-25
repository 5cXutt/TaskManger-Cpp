# ![Typing SVG](https://readme-typing-svg.demolab.com?font=Fira+Code&weight=800&size=23&pause=1000&color=0BC9F7&random=false&width=435&lines=Simple+TaskManger+In+C%2B%2B)

## ![Typing SVG](https://readme-typing-svg.demolab.com?font=Fira+Code&weight=800&size=16&duration=1&color=F70000&background=B5122900&multiline=true&repeat=false&random=false&width=435&lines=Dipendenze)

Il programma dipende dalle seguenti librerie:

- `<iostream>`: per input/output standard
- `<windows.h>`: per l'accesso alle API di Windows
- `<tlhelp32.h>`: per l'enumerazione dei processi
- `<psapi.h>`: per ottenere informazioni sulla memoria del processo
- `<string>`: per la gestione delle stringhe
- `<cstdlib>`: per l'uso della funzione `system()` per la pulizia dello schermo

## Funzioni principali

- **`GetProcessName(DWORD processId)`:** Restituisce il nome del processo dato il suo ID.
- **`ListProcesses()`:** Elenca tutti i processi attivi, escludendo "svchost.exe".
- **`PrintProcessInfo(DWORD processId)`:** Stampa informazioni dettagliate su un processo specificato.
- **`TerminateProcessById(DWORD processId)`:** Termina un processo dato il suo ID.
- **`PrintMemoryRegions(DWORD processId)`:** Stampa informazioni sulle regioni di memoria allocate per un processo.
- **`PrintDLLInfo(DWORD processId)`:** Stampa informazioni sulle DLL caricate da un processo.
- **`PrintCPUUsage(DWORD processId)`:** Stampa informazioni sull'utilizzo della CPU da parte di un processo.

## Funzione `main()`
- Un ciclo while continua ad eseguire il programma finché l'utente non sceglie di uscire inserendo `0` come ID del processo.
- All'avvio, vengono elencati tutti i processi attivi.
- L'utente può inserire l'ID di un processo per visualizzare informazioni dettagliate su di esso.
- Dopo aver visualizzato le informazioni, l'utente può scegliere di stampare le informazioni sulla memoria, sulle DLL caricate e sull'utilizzo della CPU del processo.
- L'utente può anche scegliere di terminare il processo.
- Il ciclo continua finché l'utente sceglie di uscire.

## Questo programma fornisce un'interfaccia utente semplice ma potente per gestire i processi su un sistema Windows.





