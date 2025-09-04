from urllib.parse import quote
from bs4 import BeautifulSoup

def prepare_tracked_html(base_url: str, html: str, token: str) -> str:
    soup = BeautifulSoup(html, 'html.parser')
    for a in soup.find_all('a', href=True):
        href = a['href']
        a['href'] = f"{base_url}/r/{token}?u=" + quote(href, safe='')
    pixel = soup.new_tag('img', src=f"{base_url}/o/{token}", width='1', height='1', style='display:none;')
    if soup.body:
        soup.body.append(pixel)
    else:
        soup.append(pixel)
    return str(soup)
