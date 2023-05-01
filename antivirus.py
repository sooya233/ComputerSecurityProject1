# -*-coding:utf-8 -*-
import sys
import os
import hashlib
import zlib
from io import StringIO
import scanmod
import curemod

VirusDB = [] # 악성코드 패턴은 모두 virus.kmd에 존재함
vdb = [] # 가공된 악성코드 DB가 저장된다.
vsize = [] # 악성코드의 파일 크기만 저장된다.
sdb = [] # 가공된 악성코드 DB가 저장된다. (특정 위치 검색법용)

# KMD 파일을 복호화 한다.
def DecodeKMD(fname):
    try:
        fp = open(fname, 'rb') # 복호화 대상 파일을 연다.
        buf = fp.read()
        fp.close()
        
        buf2 = buf[:-32] # 암호화 내용을 분리한다.
        fmd5 = buf[-32:] # MD5를 분리한다.
        
        f = buf2
        for i in range(3): # 암호화 내용의 MD5를 구한다.
            md5 = hashlib.md5()
            md5.update(f)
            f = md5.hexdigest()
            
        if f != fmd5: # 위 결과와 파일에서 분리된 MD5가 같은가?
            raise SystemError
        
        buf3 = ''
        for c in buf2[4:]: # 0xFF로 XOR한다.
            buf3 += chr(ord(c) ^ 0xFF)
            
        buf4 = zlib.decompress(buf3) # 압축을 해제한다.
        return buf4 # 성공한다면 복호화된 내용을 리턴한다.
    except:
        pass
    
    return None # 오류가 있다면 None을 리턴한다.
        
# virus.kmd 파일에서 악성코드 패턴을 읽는다.
def LoadVirusDB():
    buf = DecodeKMD('virus.kmd') # 악성코드 패턴을 복호화 한다.
    fp = StringIO(buf)
    
    while True:
        line = fp.readline() # 악성코드 패턴을 한 줄 읽는다.
        if not line : break
        
        line = line.strip()
        VirusDB.append(line) # 악성코드 패턴을 VirusDB에 추가한다.
        
    fp.close() # 악성코드 패턴 파일을 닫는다.
    
# VirusDB를 가공하여 vdb에 저장한다.
def MakeVirusDB() :
    for pattern in VirusDB:
        t = []
        v = pattern.split(':') # 세미콜론을 기준으로 자른다.
        
        scan_func = v[0] # 악성코드 검사 함수
        cure_func = v[1] # 악성코드 치료 함수
        
        if scan_func == 'ScanMD5': # MD5 해시를 이용한 검사인가?
            t.append(v[3]) # MD5 해시를 저장한다.
            t.append(v[4]) # 악성코드 이름을 저장한다.
            vdb.append(t) # 최종 vdb에 저장한다.
            
            size = int(v[2]) # 악성코드 파일 크기
            if vsize.count(size) == 0 : # 이미 해당 크기가 등록되었나?
                vsize.append(size)
        elif scan_func == 'ScanStr': # 특정 위치 검색법인가?
            t.append(int(v[2])) # 악성코드 진단 문자열의 위치를 저장한다.
            t.append(v[3]) # 악성코드 진단 문자열을 저장한다.
            t.append(v[4]) # 악성코드 이름을 저장한다.
            sdb.append(t) # 최종 sdb에 저장한다.
            


if __name__ == "__main__" :
    LoadVirusDB() # 악성코드 패턴을 파일에서 읽는다.
    MakeVirusDB() # 악성코드 DB를 가공한다.
    
    # 커맨드라인으로 악성코드를 검사할 수 있게한다.
    # 커맨드라인의 입력 방식을 체크한다.
    if len(sys.argv) != 2:
        print("Usage : antivirus.py [file]")
        sys.exit(0)
        
    fname = sys.argv[1] # 악성코드 검사 대상 파일
    
    ret, vname = scanmod.ScanVirus(vdb, vsize, sdb, fname) # 악성코드를 검사한다.
    if ret == True:
        print("%s : %s" %(fname, vname))
        curemod.CureDelete(fname) # 파일을 삭제하여 치료
    else:
        print("%s : ok" %(fname))
        
    