from mitmproxy import http
import os

class UpgradeAddon:
    def request(self,flow: http.HTTPFlow) -> None:
        if len(flow.request.path_components)==3 and flow.request.path_components[0] == 'routeros':
            version = flow.request.path_components[1]
            file = os.path.join(version,flow.request.path_components[2])
            if flow.request.method == 'HEAD':
                if os.path.exists(version) and os.path.isfile(file):
                    flow.response = http.Response.make(
                        status_code=200,
                        headers={
                            'Content-Type': 'application/octet-stream',
                            'Accept-Ranges':'bytes',
                            'Content-Length': str(os.stat(file).st_size),
                        }
                    )
                else:
                    flow.response = http.Response.make(status_code=404)
            elif flow.request.method == 'GET' and flow.request.path_components[2].endswith('.npk'):
                if os.path.exists(version) and os.path.isfile(file):
                    flow.response = http.Response.make(
                        status_code=200,
                        content=open(file,'rb').read(),
                        headers={'Content-Type': 'application/octet-stream',},
                    )
                else:
                    flow.response = http.Response.make(status_code=404)

async def start_listen(port):
    from mitmproxy.tools.dump import DumpMaster
    from mitmproxy import options
    opts = options.Options(listen_host='0.0.0.0',listen_port=port,mode=['reverse:https://upgrade.mikrotik.com/'])
    print(f'listening at *:{port}')
    print(f'open http://127.0.0.1:{port}')
    master = DumpMaster(opts)
    master.addons.add([UpgradeAddon()])
    try:
        await master.run()
    except KeyboardInterrupt:
        master.shutdown()
if __name__ == "__main__":
    import asyncio
    from package import check_install_package
    check_install_package(['mitmproxy'])
    print(f'ip dns static add name=upgrade.mikrotik.com address=<your ip address>')
    print(f'ip dns cache flush')
    asyncio.run(start_listen(80)) 