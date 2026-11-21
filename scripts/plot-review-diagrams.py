"""Create the two diagrams for the original BPF case and final real TCP trace."""
import argparse
import json
import os
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


PAPER = '#f1f5f8'
INK = '#15364a'
BLUE = '#136780'
ORANGE = '#a7451f'
GRAY = '#4a6375'
FONT = Path(os.environ['SYSTEMROOT'])/'Fonts/msyh.ttc'


def font(size):
    return ImageFont.truetype(str(FONT), size)


def arrow(draw, x1, x2, y, color):
    draw.line((x1, y, x2, y), fill=color, width=5)
    direction=1 if x2>x1 else -1
    draw.polygon([(x2, y), (x2-19*direction, y-11), (x2-19*direction, y+11)], fill=color)


def filtering(oracle_file, out):
    reference=json.loads(oracle_file.read_text(encoding='utf-8'))
    bpf=reference['capture_bpf']['expected_source_frame_numbers']
    udp=reference['display_sets']['UDP']
    im=Image.new('RGB',(1460,535),PAPER)
    draw=ImageDraw.Draw(im)
    draw.text((40,27),'同一份固定 PCAP，两种筛选范围',font=font(45),fill=INK)
    draw.text((40,100),'两条路径使用相同的 20 条以太网记录',font=font(27),fill=GRAY)
    for y,phase,output,numbers,color in [
        (160,'捕获 BPF  udp','按指令读取固定字节并选择输入',bpf,ORANGE),
        (330,'显示条件  UDP','按解析结果筛选保留记录',udp,BLUE),
    ]:
        draw.rounded_rectangle((44,y,690,y+128),radius=14,fill='white',outline=color,width=3)
        draw.text((69,y+14),phase,font=font(33),fill=color)
        draw.text((69,y+70),output,font=font(26),fill=INK)
        arrow(draw,724,795,y+63,color)
        draw.rounded_rectangle((830,y,1412,y+128),radius=14,fill='white',outline=color,width=3)
        draw.text((856,y+13),'命中的原始帧号',font=font(25),fill=GRAY)
        draw.text((856,y+65),'  ·  '.join(map(str,numbers)),font=font(31),fill=INK)
    draw.text((44,482),'帧 8 和 15 需要解析封装。帧 11 和 16 的字节匹配与结构状态不同。',font=font(26),fill=GRAY)
    im.save(out)


def timeline(trace_file, out):
    flow=json.loads(trace_file.read_text(encoding='utf-8'))['flow_ipv4']
    im=Image.new('RGB',(1460,782),PAPER)
    draw=ImageDraw.Draw(im)
    draw.text((40,25),'真实 IPv4 连接的双向时序',font=font(45),fill=INK)
    draw.text((42,98),f'A   {flow["a"]}',font=font(31),fill=BLUE)
    draw.text((995,98),f'B   {flow["b"]}',font=font(31),fill=ORANGE)
    a,b=221,1237
    draw.line((a,154,a,722),fill=BLUE,width=4)
    draw.line((b,154,b,722),fill=ORANGE,width=4)
    items=[r for r in flow['rows'] if r['event'] or r['payload_bytes']]
    labels={
        'SYN':'SYN 开始连接','SYN acknowledged':'SYN + ACK 确认发起端',
        'Handshake observed':'ACK 握手完成','FIN observed':'FIN 请求关闭',
        'Close exchange observed':'ACK 关闭交换结束',
    }
    for i,row in enumerate(items):
        y=193+72*i
        forward=row['direction']==0
        color=BLUE if forward else ORANGE
        arrow(draw,a if forward else b,b if forward else a,y,color)
        if row['payload_bytes']:
            event=('HTTP 请求' if forward else 'HTTP 响应')+f' {row["payload_bytes"]} B'
        else:
            event=labels[row['event']]
        label=f'#{row["id"]}   {row["elapsed_us"]/1000:.3f} ms   {event}'
        left=(a+b)/2-draw.textlength(label,font=font(28))/2
        draw.rectangle((left-14,y-22,left+draw.textlength(label,font=font(28))+14,y+20),fill=PAPER)
        draw.text((left,y-24),label,font=font(28),fill=INK)
    draw.text((42,734),'选取握手、载荷与关闭事件。时间以捕获到的第一个 SYN 为起点。',font=font(25),fill=GRAY)
    im.save(out)


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('run',type=Path)
    parser.add_argument('--oracle',type=Path,default=Path('fixtures/v2/expected.json'))
    args=parser.parse_args()
    filtering(args.oracle,args.run/'filtering-paths.png')
    timeline(args.run/'gui-review.json',args.run/'tcp-timeline.png')

