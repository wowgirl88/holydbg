#include <stdio.h>
#include <Python.h>
#include <stdlib.h>

char* readFileContent(char code[]) {
    FILE* file = fopen(code, "rb");
    if (file == NULL) {
        return NULL;
    }
    fseek(file, 0, SEEK_END);
    long fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);
    char* buffer = (char*)malloc(fileSize + 1);
    if (buffer == NULL) {
        fclose(file);
        return NULL;
    }
    size_t bytesRead = fread(buffer, 1, fileSize, file);
    if (bytesRead != fileSize) {
        free(buffer);
        fclose(file);
        return NULL;
    }
    buffer[fileSize] = '\0';
    fclose(file);
    return buffer;
}

void __attribute__((constructor)) init(void) {
    if (!Py_IsInitialized()) {
      Py_Initialize();
    }
    if (!Py_IsInitialized()) {
        fprintf(stderr, "Can't find Python interpreter or failed to initialize.\n");
        return;
    }

    char* serverContent = readFileContent("server.py");
    if (serverContent != NULL) {
        PyGILState_STATE gstate = PyGILState_Ensure();
        PyRun_SimpleString(serverContent);
        if (PyErr_Occurred()) {
            PyErr_Print();
            PyErr_Clear();
        }
        PyGILState_Release(gstate);
        free(serverContent);
    } else {
        fprintf(stderr, "Error: Could not read server code\n");
    }
}

