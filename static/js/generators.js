// ════════════════════════════════════════════════════════════════════════
//  GENERATORS MODULE — Geradores de dados brasileiros
// ════════════════════════════════════════════════════════════════════════
'use strict';

const GEN_MODULES = [
  { id:'cpf',       icon:'🪪', label:'Gerador de CPF' },
  { id:'cnpj',      icon:'🏢', label:'Gerador de CNPJ' },
  { id:'rg',        icon:'📄', label:'Gerador de RG' },
  { id:'cep',       icon:'📮', label:'Gerador de CEP' },
  { id:'pis',       icon:'💼', label:'Gerador de PIS/PASEP' },
  { id:'renavam',   icon:'🚗', label:'Gerador de RENAVAM' },
  { id:'cnh',       icon:'🪪', label:'Gerador de CNH' },
  { id:'titulo',    icon:'🗳️', label:'Gerador Título de Eleitor' },
  { id:'ie',        icon:'🏪', label:'Gerador Inscrição Estadual' },
  { id:'cartao',    icon:'💳', label:'Gerador Cartão de Crédito' },
  { id:'placa',     icon:'🚘', label:'Gerador Placa de Veículos' },
  { id:'veiculo',   icon:'🚙', label:'Gerador de Veículos' },
  { id:'conta',     icon:'🏦', label:'Gerador de Conta Bancária' },
  { id:'certidao',  icon:'📜', label:'Gerador de Certidões' },
  { id:'pessoa',    icon:'👤', label:'Gerador de Pessoas' },
  { id:'empresa',   icon:'🏭', label:'Gerador de Empresas' },
  { id:'curriculo', icon:'📋', label:'Gerador de Currículo' },
  { id:'nome',      icon:'✍️', label:'Gerador de Nomes' },
  { id:'nick',      icon:'🎮', label:'Gerador de Nicks' },
  { id:'letras',    icon:'🔤', label:'Gerador de Letras Diferentes' },
  { id:'simbolos',  icon:'✦',  label:'Símbolos para Copiar' },
  { id:'numeros',   icon:'🔢', label:'Gerador de Números Aleatórios' },
  { id:'senha',     icon:'🔑', label:'Gerador de Senha' },
  { id:'lorem',     icon:'📝', label:'Gerador de Lorem Ipsum' },
  { id:'imagem',    icon:'🖼️', label:'Gerador de Imagem' },
  { id:'sorteador', icon:'🎲', label:'Sorteador de Números' },
];

let _genActive = 'cpf';

// ─── Utilitários ─────────────────────────────────────────────────────
function _rnd(min, max) { return Math.floor(Math.random() * (max - min + 1)) + min; }
function _pick(arr) { return arr[_rnd(0, arr.length - 1)]; }
function _pad(n, len) { return String(n).padStart(len, '0'); }
function _mod11check(digits, weights) {
  const sum = digits.reduce((acc, d, i) => acc + d * weights[i], 0);
  const rem = sum % 11;
  return rem < 2 ? 0 : 11 - rem;
}
function _esc(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}
function _copyToClipboard(text) {
  navigator.clipboard.writeText(text).catch(() => {
    const ta = document.createElement('textarea');
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
  });
}

// ─── CPF ─────────────────────────────────────────────────────────────
function _genCPF(masked = true) {
  const d = Array.from({length: 9}, () => _rnd(0, 9));
  const d10 = _mod11check(d, [10,9,8,7,6,5,4,3,2]);
  const d11 = _mod11check([...d, d10], [11,10,9,8,7,6,5,4,3,2]);
  const num = [...d, d10, d11].join('');
  return masked ? num.replace(/(\d{3})(\d{3})(\d{3})(\d{2})/, '$1.$2.$3-$4') : num;
}

// ─── CNPJ ────────────────────────────────────────────────────────────
function _genCNPJ(masked = true) {
  const d = Array.from({length: 12}, () => _rnd(0, 9));
  const d13 = _mod11check(d, [5,4,3,2,9,8,7,6,5,4,3,2]);
  const d14 = _mod11check([...d, d13], [6,5,4,3,2,9,8,7,6,5,4,3,2]);
  const num = [...d, d13, d14].join('');
  return masked ? num.replace(/(\d{2})(\d{3})(\d{3})(\d{4})(\d{2})/, '$1.$2.$3/$4-$5') : num;
}

// ─── RG (SP) ─────────────────────────────────────────────────────────
function _genRG() {
  const d = Array.from({length: 8}, () => _rnd(0, 9));
  d[0] = _rnd(1, 9);
  const sum = d.reduce((acc, v, i) => acc + v * [2,3,4,5,6,7,8,9][i], 0);
  const rem = sum % 11;
  const check = rem === 0 ? '0' : rem === 1 ? 'X' : String(11 - rem);
  return d.join('').replace(/(\d{2})(\d{3})(\d{3})/, '$1.$2.$3') + '-' + check;
}

// ─── CEP ─────────────────────────────────────────────────────────────
const _CEP_RANGES = [
  [1000,9999,'SP','São Paulo'],[20000,28999,'RJ','Rio de Janeiro'],
  [29000,29999,'ES','Espírito Santo'],[30000,39999,'MG','Minas Gerais'],
  [40000,48999,'BA','Bahia'],[49000,49999,'SE','Sergipe'],
  [50000,56999,'PE','Pernambuco'],[57000,57999,'AL','Alagoas'],
  [58000,58999,'PB','Paraíba'],[59000,59999,'RN','Rio Grande do Norte'],
  [60000,63999,'CE','Ceará'],[64000,64999,'PI','Piauí'],
  [65000,65999,'MA','Maranhão'],[66000,68999,'PA','Pará'],
  [69000,69999,'AM','Amazonas'],[70000,77999,'DF','Distrito Federal'],
  [78000,78999,'MT','Mato Grosso'],[79000,79999,'MS','Mato Grosso do Sul'],
  [80000,87999,'PR','Paraná'],[88000,89999,'SC','Santa Catarina'],
  [90000,99999,'RS','Rio Grande do Sul'],
];
function _genCEP() {
  const [min, max, uf, estado] = _pick(_CEP_RANGES);
  const prefix = _pad(_rnd(min, max), 5);
  const suffix = _pad(_rnd(0, 999), 3);
  return { cep: `${prefix}-${suffix}`, uf, estado };
}

// ─── PIS/PASEP ───────────────────────────────────────────────────────
function _genPIS(masked = true) {
  const d = Array.from({length: 10}, () => _rnd(0, 9));
  const check = _mod11check(d, [3,2,9,8,7,6,5,4,3,2]);
  const num = [...d, check].join('');
  return masked ? num.replace(/(\d{3})(\d{5})(\d{2})(\d{1})/, '$1.$2.$3-$4') : num;
}

// ─── RENAVAM ─────────────────────────────────────────────────────────
function _genRENAVAM() {
  const body = Array.from({length: 8}, () => _rnd(0, 9));
  const padded = [0, 0, ...body];
  const check = _mod11check(padded, [3,2,9,8,7,6,5,4,3,2]);
  const num = [...body, check].join('');
  return num.replace(/(\d{4})(\d{4})(\d{1})/, '$1.$2-$3');
}

// ─── CNH ─────────────────────────────────────────────────────────────
function _genCNH() {
  const d = Array.from({length: 9}, () => _rnd(0, 9));
  const sum1 = d.reduce((acc, v, i) => acc + v * (9 - i), 0);
  const d1 = sum1 % 11 >= 10 ? 0 : sum1 % 11;
  const sum2 = d.reduce((acc, v, i) => acc + v * (1 + i), 0);
  const d2 = sum2 % 11 >= 10 ? 0 : sum2 % 11;
  return [...d, d1, d2].join('');
}

// ─── Título de Eleitor ───────────────────────────────────────────────
const _UF_CODES = {SP:1,MG:2,RJ:3,RS:4,BA:5,PR:6,CE:7,PE:8,SC:9,GO:10,MA:11,PB:12,PA:13,ES:14,PI:15,RN:16,AL:17,MT:18,MS:19,DF:20,SE:21,AM:22,RO:23,AC:24,AP:25,RR:26,TO:27};
const _UF_LIST = Object.keys(_UF_CODES);
function _genTitulo() {
  const uf = _pick(_UF_LIST);
  const code = _UF_CODES[uf];
  const seq = _pad(_rnd(1, 99999999), 8);
  const stateStr = _pad(code, 2);
  const digits = (seq + stateStr).split('').map(Number);
  let sum1 = digits.slice(0,8).reduce((a,v,i) => a + v*[2,3,4,5,6,7,8,9][i], 0);
  let d1 = sum1 % 11;
  if(d1 === 0) d1 = code <= 9 ? 0 : 1;
  else if(d1 === 1) d1 = code <= 9 ? 1 : 0;
  else d1 = 11 - d1;
  let sum2 = digits[8]*7 + digits[9]*8 + d1*9;
  let d2 = sum2 % 11;
  if(d2 === 0) d2 = code <= 9 ? 0 : 1;
  else if(d2 === 1) d2 = code <= 9 ? 1 : 0;
  else d2 = 11 - d2;
  return {
    numero: seq + stateStr + d1 + d2,
    formatted: seq.replace(/(\d{4})(\d{4})/, '$1 $2') + ' ' + stateStr + ' ' + d1 + d2,
    uf, zona: _pad(_rnd(1, 999), 3), secao: _pad(_rnd(1, 999), 3),
  };
}

// ─── Inscrição Estadual (SP) ─────────────────────────────────────────
const _IE_STATES = ['SP','RJ','MG','PR','SC','RS','BA','PE','CE','GO','DF'];
function _genIE(uf = 'SP') {
  const d = Array.from({length: 8}, () => _rnd(0, 9));
  d[0] = _rnd(1, 9);
  const w = [1,3,1,3,1,3,1,3];
  let sum = 0;
  d.forEach((v, i) => { const p = v * w[i]; sum += p > 9 ? Math.floor(p/10) + p%10 : p; });
  const d9 = (10 - (sum % 10)) % 10;
  const tail = [_rnd(0,9), _rnd(0,9), _rnd(0,9)];
  const num = [...d, d9, ...tail].join('');
  return { uf, ie: num.replace(/(\d{3})(\d{3})(\d{3})(\d{3})/, '$1.$2.$3/$4') };
}

// ─── Cartão de Crédito ───────────────────────────────────────────────
const _CARD_BRANDS = [
  { name:'Visa',       prefixes:['4'],                              length:16 },
  { name:'Mastercard', prefixes:['51','52','53','54','55'],         length:16 },
  { name:'Elo',        prefixes:['6362970','636368','438935','504175','636297'], length:16 },
  { name:'Hipercard',  prefixes:['606282'],                         length:16 },
  { name:'Amex',       prefixes:['34','37'],                        length:15 },
];
function _luhn(nums) {
  let sum = 0, alt = false;
  for(let i = nums.length-1; i >= 0; i--) {
    let n = nums[i];
    if(alt) { n *= 2; if(n > 9) n -= 9; }
    sum += n; alt = !alt;
  }
  return (10 - (sum % 10)) % 10;
}
function _genCartao() {
  const brand = _pick(_CARD_BRANDS);
  const prefix = _pick(brand.prefixes).split('').map(Number);
  const nums = [...prefix];
  while(nums.length < brand.length - 1) nums.push(_rnd(0, 9));
  nums.push(_luhn(nums));
  const s = nums.join('');
  const fmt = brand.length === 15
    ? s.replace(/(\d{4})(\d{6})(\d{5})/, '$1 $2 $3')
    : s.replace(/(\d{4})(\d{4})(\d{4})(\d{4})/, '$1 $2 $3 $4');
  const m = _pad(_rnd(1,12), 2);
  const y = _rnd(new Date().getFullYear()+1, new Date().getFullYear()+5);
  const cvv = _pad(_rnd(0, brand.length===15 ? 9999 : 999), brand.length===15 ? 4 : 3);
  return { brand: brand.name, number: fmt, expiry: `${m}/${y}`, cvv };
}

// ─── Placa de Veículo ────────────────────────────────────────────────
const _LS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
function _genPlaca(tipo = null) {
  const L = () => _LS[_rnd(0, 25)];
  const D = () => _rnd(0, 9);
  const useMercosul = tipo === 'mercosul' || (tipo === null && Math.random() > 0.5);
  return useMercosul
    ? `${L()}${L()}${L()}${D()}${L()}${D()}${D()}`  // ABC1D23
    : `${L()}${L()}${L()}-${D()}${D()}${D()}${D()}`; // ABC-1234
}

// ─── Veículo ─────────────────────────────────────────────────────────
const _MARCAS = ['Volkswagen','Fiat','Chevrolet','Ford','Toyota','Honda','Hyundai','Renault','Jeep','Nissan','Peugeot','Citroën'];
const _MODELOS = {
  'Volkswagen':['Gol','Polo','Virtus','T-Cross','Taos','Nivus','Jetta','Amarok'],
  'Fiat':['Strada','Uno','Mobi','Pulse','Cronos','Toro','Ducato'],
  'Chevrolet':['Onix','Tracker','S10','Spin','Montana','Equinox'],
  'Ford':['Ka','EcoSport','Ranger','Territory','Bronco Sport'],
  'Toyota':['Corolla','Hilux','SW4','Yaris','Prius','Rav4'],
  'Honda':['HR-V','City','Civic','CR-V','WR-V'],
  'Hyundai':['HB20','Creta','Tucson','Santa Fe','i30'],
  'Renault':['Kwid','Sandero','Logan','Duster','Oroch'],
  'Jeep':['Renegade','Compass','Commander'],
  'Nissan':['Kicks','Versa','Frontier'],
  'Peugeot':['208','2008','3008'],
  'Citroën':['C3','C4 Cactus','Berlingo'],
};
const _CORES = ['Branco','Prata','Preto','Cinza','Vermelho','Azul','Verde','Bege','Marrom'];
const _COMBUSTIVEIS = ['Flex (Álcool/Gasolina)','Gasolina','Diesel','Elétrico','Híbrido'];
const _CATEGORIAS = ['Automóvel','Camionete','SUV','Furgão'];
function _genVeiculo() {
  const marca = _pick(_MARCAS);
  const modelo = _pick(_MODELOS[marca]);
  const ano = _rnd(2000, new Date().getFullYear());
  return { marca, modelo, ano, cor: _pick(_CORES), combustivel: _pick(_COMBUSTIVEIS), placa: _genPlaca(), categoria: _pick(_CATEGORIAS) };
}

// ─── Conta Bancária ──────────────────────────────────────────────────
const _BANCOS = [
  {codigo:'001',nome:'Banco do Brasil'},{codigo:'033',nome:'Santander'},
  {codigo:'104',nome:'Caixa Econômica Federal'},{codigo:'237',nome:'Bradesco'},
  {codigo:'341',nome:'Itaú'},{codigo:'260',nome:'Nubank'},
  {codigo:'077',nome:'Banco Inter'},{codigo:'290',nome:'PagSeguro'},
  {codigo:'336',nome:'Banco C6'},{codigo:'756',nome:'Sicoob'},
  {codigo:'748',nome:'Sicredi'},{codigo:'212',nome:'Banco Original'},
  {codigo:'735',nome:'Neon'},{codigo:'208',nome:'BTG Pactual'},
];
const _TIPOS_CONTA = ['Corrente','Poupança','Salário'];
function _genConta() {
  const banco = _pick(_BANCOS);
  return {
    banco: `${banco.codigo} - ${banco.nome}`,
    agencia: `${_pad(_rnd(1000,9999),4)}-${_rnd(0,9)}`,
    conta: `${_pad(_rnd(10000,999999),6)}-${_rnd(0,9)}`,
    tipo: _pick(_TIPOS_CONTA),
  };
}

// ─── Certidão ────────────────────────────────────────────────────────
const _TIPOS_CERT = ['Nascimento','Casamento','Óbito'];
const _CARTORIOS = ['1º Ofício de Registro Civil','2º Ofício de Registro Civil','3º Ofício de Registro Civil','Cartório Paz e Bem','Tabelionato de Notas'];
function _genCertidao() {
  const tipo = _pick(_TIPOS_CERT);
  const uf = _pick(_UF_LIST);
  const ano = _rnd(1970, 2024);
  const matricula = `${_pad(_rnd(1,99999),5)} ${_pad(_rnd(1,99),2)} ${ano} 2 ${_pad(_rnd(1,99),2)} ${_pad(_rnd(1,9999),4)} ${_rnd(100,999)} ${_pad(_rnd(10000,99999),5)}`;
  const dt = `${_pad(_rnd(1,28),2)}/${_pad(_rnd(1,12),2)}/${ano}`;
  return { tipo, matricula, cartorio: _pick(_CARTORIOS), uf, data: dt };
}

// ─── Nomes ───────────────────────────────────────────────────────────
const _PRENOMES_M = ['Miguel','Arthur','Heitor','Théo','Davi','Gabriel','Lucas','Matheus','João','Pedro','Enzo','Lorenzo','Gustavo','Nicolas','Felipe','Rafael','Samuel','Leonardo','Bernardo','Henrique'];
const _PRENOMES_F = ['Alice','Sofia','Helena','Valentina','Laura','Isabella','Manuela','Júlia','Heloísa','Luíza','Maria','Lara','Beatriz','Letícia','Ana','Clara','Vitória','Isadora','Lívia','Camila'];
const _SOBRENOMES = ['Silva','Santos','Oliveira','Souza','Rodrigues','Ferreira','Alves','Lima','Gomes','Costa','Ribeiro','Martins','Carvalho','Almeida','Lopes','Sousa','Fernandes','Pereira','Nascimento','Barbosa','Gonçalves','Cavalcante','Moreira','Castro','Araújo','Nunes','Dias','Cardoso','Pinto','Moura','Mendes','Machado','Correia','Freitas','Teixeira','Ramos','Cunha','Monteiro','Duarte','Borges'];
function _genNome(sexo = null) {
  const s = sexo || (Math.random() > 0.5 ? 'M' : 'F');
  const primeiro = s === 'M' ? _pick(_PRENOMES_M) : _pick(_PRENOMES_F);
  return { nome: `${primeiro} ${_pick(_SOBRENOMES)} ${_pick(_SOBRENOMES)}`, sexo: s };
}
const _DOMINIOS_EMAIL = ['gmail.com','yahoo.com.br','hotmail.com','outlook.com','icloud.com','uol.com.br'];
function _nomeToEmail(nome) {
  const p = nome.normalize('NFD').replace(/[̀-ͯ]/g,'').toLowerCase().split(' ');
  const user = p[0] + (Math.random()>0.5 ? '.' + p[p.length-1] : _rnd(1,999));
  return `${user}@${_pick(_DOMINIOS_EMAIL)}`;
}
const _DDDS = [11,21,31,41,51,61,71,81,85,91,92,51,48,65,62,83,84,86,95,96,97,98,99];
function _genPhone() {
  const ddd = _pick(_DDDS);
  return `(${ddd}) 9${_pad(_rnd(1000,9999),4)}-${_pad(_rnd(1000,9999),4)}`;
}

// ─── Nicks ───────────────────────────────────────────────────────────
const _NICK_ADJ = ['Dark','Shadow','Wolf','Fire','Iron','Storm','Cyber','Pixel','Neo','Ghost','Dead','Night','Steel','Blood','Crystal','Void','Toxic','Hyper','Ultra','Chaos'];
const _NICK_NOUNS = ['Hacker','Hunter','Killer','Master','Rider','Knight','Dragon','Phoenix','Ninja','Warrior','Sniper','Ranger','Blade','Force','Strike','Coder','Byte','Zero','Root','Shell'];
function _genNick() {
  const sep = _pick(['','_','.','x','__']);
  const num = Math.random() > 0.4 ? String(_rnd(1,9999)) : '';
  return _pick(_NICK_ADJ) + sep + _pick(_NICK_NOUNS) + num;
}

// ─── Letras Diferentes ───────────────────────────────────────────────
function _toFontStyle(text, style) {
  const cp = c => c.codePointAt(0);
  return [...text].map(c => {
    const code = cp(c);
    const isUpper = code >= 65 && code <= 90;
    const isLower = code >= 97 && code <= 122;
    const isDigit = code >= 48 && code <= 57;
    switch(style) {
      case 'bold':
        if(isUpper) return String.fromCodePoint(0x1D400 + code - 65);
        if(isLower) return String.fromCodePoint(0x1D41A + code - 97);
        return c;
      case 'italic':
        if(isUpper) return String.fromCodePoint(0x1D434 + code - 65);
        if(isLower) return String.fromCodePoint(0x1D44E + code - 97);
        return c;
      case 'script':
        if(isUpper) return String.fromCodePoint(0x1D49C + code - 65);
        if(isLower) return String.fromCodePoint(0x1D4B6 + code - 97);
        return c;
      case 'double':
        if(isUpper) return String.fromCodePoint(0x1D538 + code - 65);
        if(isLower) return String.fromCodePoint(0x1D552 + code - 97);
        if(isDigit) return String.fromCodePoint(0x1D7D8 + code - 48);
        return c;
      case 'mono':
        if(isUpper) return String.fromCodePoint(0x1D670 + code - 65);
        if(isLower) return String.fromCodePoint(0x1D68A + code - 97);
        if(isDigit) return String.fromCodePoint(0x1D7F6 + code - 48);
        return c;
      case 'smallcaps':
        return 'aᴀ bʙ cᴄ dᴅ eᴇ fꜰ gɢ hʜ iɪ jᴊ kᴋ lʟ mᴍ nɴ oᴏ pᴘ qq rʀ sꜱ tᴛ uᴜ vᴠ wᴡ xx yʏ zᴢ'.split(' ').find(x=>x[0]===c.toLowerCase())?.[1] || c;
      case 'circled':
        if(isUpper) return String.fromCodePoint(0x24B6 + code - 65);
        if(isLower) return String.fromCodePoint(0x24D0 + code - 97);
        if(isDigit) return ['⓪','①','②','③','④','⑤','⑥','⑦','⑧','⑨'][code-48] || c;
        return c;
      case 'strike':
        return c + '̶';
      case 'underline':
        return c + '̲';
      default:
        return c;
    }
  }).join('');
}
const _FONT_STYLES = [
  {id:'bold',     label:'𝐍𝐞𝐠𝐫𝐢𝐭𝐨'},
  {id:'italic',   label:'𝐼𝑡á𝑙𝑖𝑐𝑜'},
  {id:'script',   label:'𝒞𝒶𝓁𝒾𝑔𝓇á𝒻𝒾𝒸𝑜'},
  {id:'double',   label:'𝔻𝕦𝕡𝕝𝕠'},
  {id:'mono',     label:'𝙼𝚘𝚗𝚘'},
  {id:'smallcaps',label:'Sᴍᴀʟʟ Cᴀᴘs'},
  {id:'circled',  label:'Ⓒⓘⓡⓒⓛⓔⓓ'},
  {id:'strike',   label:'S̶t̶r̶i̶k̶e̶'},
  {id:'underline',label:'U͟n͟d͟e͟r͟l͟i͟n͟e͟'},
];

// ─── Símbolos ─────────────────────────────────────────────────────────
const _SIMBOLOS_CATS = [
  {cat:'Setas',     syms:['←','→','↑','↓','↔','↕','⇐','⇒','⇑','⇓','⇔','⇕','↩','↪','↫','↬','↭','↮','↯','↰','↱','↲','↳','↴','↵','↶','↷','↺','↻','⟵','⟶','⟷']},
  {cat:'Matemática',syms:['∞','∑','∏','√','∛','∜','∂','∇','∫','∬','∭','±','∓','×','÷','≠','≤','≥','≈','≡','≢','∈','∉','⊂','⊃','⊆','⊇','∩','∪','∧','∨','¬','∀','∃']},
  {cat:'Monetário', syms:['$','€','£','¥','₩','₿','₽','₹','₺','₲','₦','₱','₴','₵','₸','¢','฿','৳','₭','₮','₡','₫','₪','₫']},
  {cat:'Estrelas',  syms:['★','☆','✦','✧','✩','✪','✫','✬','✭','✮','✯','✰','⭐','🌟','✨','💫','⋆','✷','✸','✹','✺','✻','✼','✽','✾','✿']},
  {cat:'Formas',    syms:['♠','♥','♦','♣','♤','♡','♢','♧','▲','▼','◆','◇','●','○','■','□','▪','▫','▸','▹','◂','◃','△','▽','◈','◉','◎']},
  {cat:'Especiais', syms:['©','®','™','℗','℠','°','µ','§','¶','†','‡','‰','‱','№','℃','℉','Ω','Å','ℓ','℘','∞','⌘','⌥','⇧','⌫','⌦','⌃','⌤','⎋','⏎']},
  {cat:'Texto',     syms:['✓','✗','✘','✔','✕','✖','★','☆','●','○','■','□','◆','◇','▲','▼','◉','◎','⊕','⊗','⊙','⊘','⊛','⊜','⊝']},
  {cat:'Teclado',   syms:['⌘','⌥','⇧','⌫','⌦','⌃','⌤','⎋','⏎','⇥','⇤','⏏','⎀','⎁','⎂','⎃','⎄','⎅','⎆','⎇','⌨','⏚','⏛','⏜','⏝','⏞','⏟']},
];

// ─── Senha ───────────────────────────────────────────────────────────
function _genSenha(length = 16, lower = true, upper = true, numbers = true, symbols = true) {
  let chars = '';
  const pools = [];
  if(lower)   { chars += 'abcdefghijklmnopqrstuvwxyz'; pools.push('abcdefghijklmnopqrstuvwxyz'); }
  if(upper)   { chars += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'; pools.push('ABCDEFGHIJKLMNOPQRSTUVWXYZ'); }
  if(numbers) { chars += '0123456789'; pools.push('0123456789'); }
  if(symbols) { chars += '!@#$%^&*()_+-=[]{}|;:,.<>?'; pools.push('!@#$%^&*()_+-=[]{}|;:,.<>?'); }
  if(!chars) chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
  let pw = pools.map(p => p[_rnd(0, p.length-1)]).join('');
  while(pw.length < length) pw += chars[_rnd(0, chars.length-1)];
  return pw.split('').sort(() => Math.random()-0.5).join('').slice(0, length);
}

// ─── Lorem Ipsum ─────────────────────────────────────────────────────
const _LOREM_WORDS = ['lorem','ipsum','dolor','sit','amet','consectetur','adipiscing','elit','sed','do','eiusmod','tempor','incididunt','ut','labore','et','dolore','magna','aliqua','enim','ad','minim','veniam','quis','nostrud','exercitation','ullamco','laboris','nisi','aliquip','ex','ea','commodo','consequat','duis','aute','irure','in','reprehenderit','voluptate','velit','esse','cillum','fugiat','nulla','pariatur','excepteur','sint','occaecat','cupidatat','non','proident','sunt','culpa','qui','officia','deserunt','mollit','anim','est','laborum'];
function _genLorem(paras = 1) {
  return Array.from({length: paras}, (_, pi) => {
    const nSent = _rnd(3, 6);
    return Array.from({length: nSent}, (__, si) => {
      const nWords = _rnd(8, 16);
      let words = Array.from({length: nWords}, () => _pick(_LOREM_WORDS));
      if(pi === 0 && si === 0) { words[0] = 'Lorem'; if(words[1]) words[1] = 'ipsum'; }
      words[0] = words[0].charAt(0).toUpperCase() + words[0].slice(1);
      return words.join(' ') + '.';
    }).join(' ');
  });
}

// ─── Pessoa ───────────────────────────────────────────────────────────
function _genPessoa() {
  const n = _genNome();
  const birthY = _rnd(1960, 2005);
  const birthM = _pad(_rnd(1,12),2);
  const birthD = _pad(_rnd(1,28),2);
  const cep = _genCEP();
  const ruas = ['Rua das Flores','Av. Paulista','Rua do Sol','Travessa das Pedras','Al. Santos','Rua XV de Novembro','Av. Brasil','Rua São João'];
  return {
    nome: n.nome, sexo: n.sexo,
    nascimento: `${birthD}/${birthM}/${birthY}`,
    idade: new Date().getFullYear() - birthY,
    cpf: _genCPF(true), rg: _genRG(), cnh: _genCNH(), pis: _genPIS(true),
    titulo: _genTitulo().formatted,
    email: _nomeToEmail(n.nome), telefone: _genPhone(),
    cep: `${cep.cep} – ${cep.estado}`,
    endereco: `${_pick(ruas)}, ${_rnd(1,9999)} – ${cep.uf}`,
  };
}

// ─── Empresa ──────────────────────────────────────────────────────────
const _TIPOS_EMP = ['Ltda','S.A.','MEI','ME','EPP','EIRELI','SLU'];
const _RAMOS = ['Tecnologia','Comércio','Serviços','Indústria','Consultoria','Logística','Saúde','Educação','Construção','Alimentação'];
const _EMP_ADJ = ['Digital','Solutions','Brasil','Tech','Group','Sistemas','Express','Prime','Global','Plus','Net','Connect','Smart','Fast','Pro'];
const _EMP_NOME = ['Alpha','Beta','Gamma','Delta','Sigma','Nova','Ultra','Star','Top','Best','Apex','Peak','Core','Edge','Link'];
function _genEmpresa() {
  const tipo = _pick(_TIPOS_EMP);
  const nome = `${_pick(_EMP_NOME)} ${_pick(_EMP_ADJ)}`;
  const razao = `${nome} ${tipo}`;
  const cnpj = _genCNPJ(true);
  const ie = _genIE();
  const ramo = _pick(_RAMOS);
  const email = `contato@${nome.toLowerCase().replace(/\s+/g,'')}.com.br`;
  const cep = _genCEP();
  return { razao_social: razao, nome_fantasia: nome.replace(/\s+/g,''), cnpj, ie: ie.ie, tipo, ramo, email, telefone: _genPhone(), cep: `${cep.cep} – ${cep.estado}` };
}

// ─── Currículo ────────────────────────────────────────────────────────
const _SKILLS_POOLS = [
  ['JavaScript','React','Node.js','TypeScript','CSS3','HTML5','Git'],
  ['Python','Django','FastAPI','PostgreSQL','Docker','Linux','Bash'],
  ['Java','Spring Boot','MySQL','AWS','Kubernetes','CI/CD','Maven'],
  ['PHP','Laravel','Vue.js','MySQL','Redis','REST APIs','Nginx'],
  ['C#','.NET','SQL Server','Azure','WPF','Entity Framework','Git'],
  ['Go','Gin','gRPC','PostgreSQL','Kafka','Docker','Prometheus'],
];
const _CARGOS = ['Desenvolvedor(a) Pleno','Desenvolvedor(a) Sênior','Analista de Sistemas','Engenheiro(a) de Software','Analista de TI','Tech Lead','DevOps Engineer'];
const _EMPRESAS_JOB = ['TechCorp Brasil','Softex Solutions','DataBridge Ltda','CloudMaster S.A.','InnovaCode ME','AgileWorks','ByteForce Digital'];
function _genCurriculo() {
  const p = _genPessoa();
  const skills = _pick(_SKILLS_POOLS);
  const curY = new Date().getFullYear();
  const jobs = [
    { cargo: _pick(_CARGOS), empresa: _pick(_EMPRESAS_JOB), inicio: curY - _rnd(1,3), fim: 'Atual' },
    { cargo: _pick(_CARGOS), empresa: _pick(_EMPRESAS_JOB), inicio: curY - _rnd(5,8), fim: curY - _rnd(1,4) },
  ];
  const edu = { curso: _pick(['Ciência da Computação','Sistemas de Informação','Engenharia de Software','Análise e Desenvolvimento de Sistemas','Redes de Computadores']), instituicao: _pick(['USP','UNICAMP','UFRJ','UFMG','PUCSP','Mackenzie','FIAP','UNIP']), ano: curY - _rnd(3,10) };
  return { pessoa: p, skills, jobs, edu };
}

// ════════════════════════════════════════════════════════════════════════
//  UI FUNCTIONS
// ════════════════════════════════════════════════════════════════════════

function showGeneratorsPage() {
  const view = document.getElementById('view-generators');
  if(!view) return;
  if(!document.getElementById('gen-sidebar')) {
    view.innerHTML = `
      <div class="gen-layout">
        <aside class="gen-sidebar" id="gen-sidebar">
          <div class="gen-sidebar-search">
            <input type="text" placeholder="Filtrar..." id="gen-filter-input" oninput="genFilterSidebar()" autocomplete="off">
          </div>
          <div id="gen-sidebar-list">
            ${GEN_MODULES.map(m => `
              <button class="gen-nav-item ${m.id === _genActive ? 'active' : ''}"
                      id="gen-nav-${m.id}" onclick="genActivate('${m.id}')">
                <span class="gen-nav-icon">${m.icon}</span>
                <span class="gen-nav-label">${m.label}</span>
              </button>
            `).join('')}
          </div>
        </aside>
        <main class="gen-main" id="gen-main"></main>
      </div>`;
  }
  genActivate(_genActive);
}

function genFilterSidebar() {
  const q = (document.getElementById('gen-filter-input')?.value || '').toLowerCase();
  GEN_MODULES.forEach(m => {
    const el = document.getElementById(`gen-nav-${m.id}`);
    if(el) el.style.display = (!q || m.label.toLowerCase().includes(q)) ? '' : 'none';
  });
}

function genActivate(id) {
  _genActive = id;
  document.querySelectorAll('.gen-nav-item').forEach(el => el.classList.remove('active'));
  document.getElementById(`gen-nav-${id}`)?.classList.add('active');
  const main = document.getElementById('gen-main');
  if(!main) return;
  const renders = {
    cpf: _genRender_cpf, cnpj: _genRender_cnpj, rg: _genRender_rg,
    cep: _genRender_cep, pis: _genRender_pis, renavam: _genRender_renavam,
    cnh: _genRender_cnh, titulo: _genRender_titulo, ie: _genRender_ie,
    cartao: _genRender_cartao, placa: _genRender_placa, veiculo: _genRender_veiculo,
    conta: _genRender_conta, certidao: _genRender_certidao, pessoa: _genRender_pessoa,
    empresa: _genRender_empresa, curriculo: _genRender_curriculo, nome: _genRender_nome,
    nick: _genRender_nick, letras: _genRender_letras, simbolos: _genRender_simbolos,
    numeros: _genRender_numeros, senha: _genRender_senha, lorem: _genRender_lorem,
    imagem: _genRender_imagem, sorteador: _genRender_sorteador,
  };
  const fn = renders[id];
  if(fn) { main.innerHTML = fn(); _genBindEvents(id); }
}

function genCopyText(text) {
  _copyToClipboard(text);
  // flash the button
  event?.target && (event.target.textContent = '✓ Copiado!', setTimeout(() => {
    if(event?.target) event.target.textContent = '📋 Copiar';
  }, 1500));
}

function _genField(label, value, copyable = true) {
  const id = 'gf_' + Math.random().toString(36).slice(2,8);
  const copy = copyable ? `<button class="gen-copy-btn" onclick="genCopyText(document.getElementById('${id}').textContent)">📋</button>` : '';
  return `<div class="gen-field"><span class="gen-field-label">${_esc(label)}</span><span class="gen-field-value" id="${id}">${_esc(String(value))}</span>${copy}</div>`;
}

function _genCard(title, content, onGenerate = null) {
  const genBtnId = 'gen-btn-' + Math.random().toString(36).slice(2,8);
  const btn = onGenerate ? `<button class="btn btn-primary" id="${genBtnId}">${onGenerate}</button>` : '';
  return `<div class="gen-card"><div class="gen-card-hdr">${title}</div>${content}${btn ? '<div class="gen-card-footer">' + btn + '</div>' : ''}</div>`;
}

// ════════════════════════════════════════════════════════════════════════
//  RENDER FUNCTIONS PER GENERATOR
// ════════════════════════════════════════════════════════════════════════

function _genRender_cpf() {
  const data = _genCPF(true);
  return `
    <div class="gen-top-bar">
      <h2>🪪 Gerador de CPF</h2>
      <button class="btn btn-primary" onclick="genActivate('cpf')">↻ Gerar Novo</button>
    </div>
    ${_genCard('CPF Gerado',`
      <div class="gen-number-big" id="cpf-val">${_esc(data)}</div>
      <div style="display:flex;gap:8px;margin-top:12px;flex-wrap:wrap">
        <button class="btn btn-secondary" onclick="genCopyText(document.getElementById('cpf-val').textContent)">📋 Copiar</button>
        <button class="btn btn-secondary" onclick="document.getElementById('cpf-val').textContent=_genCPF(false)">Sem Máscara</button>
        <button class="btn btn-secondary" onclick="document.getElementById('cpf-val').textContent=_genCPF(true)">Com Máscara</button>
      </div>
    `)}
    <div class="gen-info-box">CPF é o Cadastro de Pessoas Físicas, emitido pela Receita Federal do Brasil. Gerado com algoritmo de dígitos verificadores válido.</div>`;
}

function _genRender_cnpj() {
  const data = _genCNPJ(true);
  return `
    <div class="gen-top-bar">
      <h2>🏢 Gerador de CNPJ</h2>
      <button class="btn btn-primary" onclick="genActivate('cnpj')">↻ Gerar Novo</button>
    </div>
    ${_genCard('CNPJ Gerado',`
      <div class="gen-number-big" id="cnpj-val">${_esc(data)}</div>
      <div style="display:flex;gap:8px;margin-top:12px;flex-wrap:wrap">
        <button class="btn btn-secondary" onclick="genCopyText(document.getElementById('cnpj-val').textContent)">📋 Copiar</button>
        <button class="btn btn-secondary" onclick="document.getElementById('cnpj-val').textContent=_genCNPJ(false)">Sem Máscara</button>
        <button class="btn btn-secondary" onclick="document.getElementById('cnpj-val').textContent=_genCNPJ(true)">Com Máscara</button>
      </div>
    `)}
    <div class="gen-info-box">CNPJ é o Cadastro Nacional de Pessoas Jurídicas. Gerado com algoritmo oficial de dois dígitos verificadores.</div>`;
}

function _genRender_rg() {
  const data = _genRG();
  return `
    <div class="gen-top-bar">
      <h2>📄 Gerador de RG</h2>
      <button class="btn btn-primary" onclick="genActivate('rg')">↻ Gerar Novo</button>
    </div>
    ${_genCard('RG Gerado (SP)',`
      <div class="gen-number-big" id="rg-val">${_esc(data)}</div>
      <button class="btn btn-secondary" style="margin-top:12px" onclick="genCopyText(document.getElementById('rg-val').textContent)">📋 Copiar</button>
    `)}
    <div class="gen-info-box">RG no formato do Estado de São Paulo: XX.XXX.XXX-D onde D pode ser dígito ou X.</div>`;
}

function _genRender_cep() {
  const data = _genCEP();
  return `
    <div class="gen-top-bar">
      <h2>📮 Gerador de CEP</h2>
      <button class="btn btn-primary" onclick="genActivate('cep')">↻ Gerar Novo</button>
    </div>
    ${_genCard('CEP Gerado',`
      <div id="cep-output">
        ${_genField('CEP', data.cep)}
        ${_genField('Estado', data.estado)}
        ${_genField('UF', data.uf)}
      </div>
    `)}
    <div class="gen-info-box">CEP gerado dentro dos intervalos oficiais dos Correios por estado.</div>`;
}

function _genRender_pis() {
  const data = _genPIS(true);
  return `
    <div class="gen-top-bar">
      <h2>💼 Gerador de PIS/PASEP</h2>
      <button class="btn btn-primary" onclick="genActivate('pis')">↻ Gerar Novo</button>
    </div>
    ${_genCard('PIS/PASEP Gerado',`
      <div class="gen-number-big" id="pis-val">${_esc(data)}</div>
      <div style="display:flex;gap:8px;margin-top:12px">
        <button class="btn btn-secondary" onclick="genCopyText(document.getElementById('pis-val').textContent)">📋 Copiar</button>
        <button class="btn btn-secondary" onclick="document.getElementById('pis-val').textContent=_genPIS(false)">Sem Máscara</button>
        <button class="btn btn-secondary" onclick="document.getElementById('pis-val').textContent=_genPIS(true)">Com Máscara</button>
      </div>
    `)}
    <div class="gen-info-box">PIS (trabalhador privado) e PASEP (servidor público) — 11 dígitos com dígito verificador.</div>`;
}

function _genRender_renavam() {
  const data = _genRENAVAM();
  return `
    <div class="gen-top-bar">
      <h2>🚗 Gerador de RENAVAM</h2>
      <button class="btn btn-primary" onclick="genActivate('renavam')">↻ Gerar Novo</button>
    </div>
    ${_genCard('RENAVAM Gerado',`
      <div class="gen-number-big" id="renavam-val">${_esc(data)}</div>
      <button class="btn btn-secondary" style="margin-top:12px" onclick="genCopyText(document.getElementById('renavam-val').textContent)">📋 Copiar</button>
    `)}
    <div class="gen-info-box">RENAVAM — Registro Nacional de Veículos Automotores. 9 dígitos + dígito verificador.</div>`;
}

function _genRender_cnh() {
  const data = _genCNH();
  return `
    <div class="gen-top-bar">
      <h2>🪪 Gerador de CNH</h2>
      <button class="btn btn-primary" onclick="genActivate('cnh')">↻ Gerar Novo</button>
    </div>
    ${_genCard('CNH Gerado',`
      <div class="gen-number-big" id="cnh-val">${_esc(data)}</div>
      <button class="btn btn-secondary" style="margin-top:12px" onclick="genCopyText(document.getElementById('cnh-val').textContent)">📋 Copiar</button>
    `)}
    <div class="gen-info-box">CNH — Carteira Nacional de Habilitação. 11 dígitos com dois dígitos verificadores.</div>`;
}

function _genRender_titulo() {
  const data = _genTitulo();
  return `
    <div class="gen-top-bar">
      <h2>🗳️ Gerador de Título de Eleitor</h2>
      <button class="btn btn-primary" onclick="genActivate('titulo')">↻ Gerar Novo</button>
    </div>
    ${_genCard('Título de Eleitor',`
      <div id="titulo-output">
        ${_genField('Número', data.formatted)}
        ${_genField('UF', data.uf)}
        ${_genField('Zona', data.zona)}
        ${_genField('Seção', data.secao)}
      </div>
    `)}
    <div class="gen-info-box">12 dígitos: sequência (8) + código do estado (2) + dígitos verificadores (2).</div>`;
}

function _genRender_ie() {
  const uf = _pick(_IE_STATES);
  const data = _genIE(uf);
  return `
    <div class="gen-top-bar">
      <h2>🏪 Gerador de Inscrição Estadual</h2>
      <button class="btn btn-primary" onclick="genActivate('ie')">↻ Gerar Novo</button>
    </div>
    <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px">
      ${_IE_STATES.map(s=>`<button class="bbh-cat-pill ${s===uf?'active':''}" onclick="genActivate('ie')">${s}</button>`).join('')}
    </div>
    ${_genCard(`IE — ${uf}`,`
      <div id="ie-output">
        ${_genField('Inscrição Estadual', data.ie)}
        ${_genField('Estado', data.uf)}
      </div>
    `)}`;
}

function _genRender_cartao() {
  const data = _genCartao();
  return `
    <div class="gen-top-bar">
      <h2>💳 Gerador de Cartão de Crédito</h2>
      <button class="btn btn-primary" onclick="genActivate('cartao')">↻ Gerar Novo</button>
    </div>
    ${_genCard('Cartão Gerado',`
      <div id="cartao-output">
        ${_genField('Bandeira', data.brand)}
        ${_genField('Número', data.number)}
        ${_genField('Validade', data.expiry)}
        ${_genField('CVV', data.cvv)}
      </div>
    `)}
    <div class="gen-info-box">⚠️ Gerado com algoritmo de Luhn. Número fictício — não possui fundos nem é ligado a nenhuma conta real.</div>`;
}

function _genRender_placa() {
  const mercosul = _genPlaca('mercosul');
  const antiga = _genPlaca('antiga');
  return `
    <div class="gen-top-bar">
      <h2>🚘 Gerador de Placa de Veículo</h2>
      <button class="btn btn-primary" onclick="genActivate('placa')">↻ Gerar Novo</button>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">
      ${_genCard('Padrão Mercosul (ABC1D23)',`
        <div class="gen-number-big gen-placa-mercosul" id="placa-m">${_esc(mercosul)}</div>
        <button class="btn btn-secondary" style="margin-top:12px" onclick="genCopyText(document.getElementById('placa-m').textContent)">📋 Copiar</button>
      `)}
      ${_genCard('Padrão Antigo (ABC-1234)',`
        <div class="gen-number-big" id="placa-a">${_esc(antiga)}</div>
        <button class="btn btn-secondary" style="margin-top:12px" onclick="genCopyText(document.getElementById('placa-a').textContent)">📋 Copiar</button>
      `)}
    </div>`;
}

function _genRender_veiculo() {
  const v = _genVeiculo();
  return `
    <div class="gen-top-bar">
      <h2>🚙 Gerador de Veículos</h2>
      <button class="btn btn-primary" onclick="genActivate('veiculo')">↻ Gerar Novo</button>
    </div>
    ${_genCard('Veículo Gerado',`
      <div id="veiculo-output">
        ${_genField('Marca', v.marca)}
        ${_genField('Modelo', v.modelo)}
        ${_genField('Ano', v.ano)}
        ${_genField('Cor', v.cor)}
        ${_genField('Combustível', v.combustivel)}
        ${_genField('Categoria', v.categoria)}
        ${_genField('Placa', v.placa)}
      </div>
    `)}`;
}

function _genRender_conta() {
  const c = _genConta();
  return `
    <div class="gen-top-bar">
      <h2>🏦 Gerador de Conta Bancária</h2>
      <button class="btn btn-primary" onclick="genActivate('conta')">↻ Gerar Novo</button>
    </div>
    ${_genCard('Dados Bancários',`
      <div id="conta-output">
        ${_genField('Banco', c.banco)}
        ${_genField('Agência', c.agencia)}
        ${_genField('Conta', c.conta)}
        ${_genField('Tipo', c.tipo)}
      </div>
    `)}
    <div class="gen-info-box">Dados fictícios para testes. Não representa conta bancária real.</div>`;
}

function _genRender_certidao() {
  const c = _genCertidao();
  return `
    <div class="gen-top-bar">
      <h2>📜 Gerador de Certidões</h2>
      <button class="btn btn-primary" onclick="genActivate('certidao')">↻ Gerar Novo</button>
    </div>
    ${_genCard(`Certidão de ${c.tipo}`,`
      <div id="certidao-output">
        ${_genField('Tipo', c.tipo)}
        ${_genField('Matrícula', c.matricula)}
        ${_genField('Cartório', c.cartorio)}
        ${_genField('Estado', c.uf)}
        ${_genField('Data', c.data)}
      </div>
    `)}`;
}

function _genRender_pessoa() {
  const p = _genPessoa();
  return `
    <div class="gen-top-bar">
      <h2>👤 Gerador de Pessoas</h2>
      <button class="btn btn-primary" onclick="genActivate('pessoa')">↻ Gerar Novo</button>
    </div>
    ${_genCard('Pessoa Gerada',`
      <div id="pessoa-output">
        ${_genField('Nome', p.nome)}
        ${_genField('Sexo', p.sexo === 'M' ? 'Masculino' : 'Feminino')}
        ${_genField('Data de Nascimento', p.nascimento)}
        ${_genField('Idade', p.idade + ' anos')}
        ${_genField('CPF', p.cpf)}
        ${_genField('RG', p.rg)}
        ${_genField('CNH', p.cnh)}
        ${_genField('PIS/PASEP', p.pis)}
        ${_genField('Título de Eleitor', p.titulo)}
        ${_genField('E-mail', p.email)}
        ${_genField('Telefone', p.telefone)}
        ${_genField('CEP', p.cep)}
        ${_genField('Endereço', p.endereco)}
      </div>
      <button class="btn btn-secondary" style="margin-top:12px" onclick="genCopyText(Object.values(window._lastPessoa||{}).join('\\n'))">📋 Copiar Tudo</button>
    `)}`;
}

function _genRender_empresa() {
  const e = _genEmpresa();
  return `
    <div class="gen-top-bar">
      <h2>🏭 Gerador de Empresas</h2>
      <button class="btn btn-primary" onclick="genActivate('empresa')">↻ Gerar Novo</button>
    </div>
    ${_genCard('Empresa Gerada',`
      <div id="empresa-output">
        ${_genField('Razão Social', e.razao_social)}
        ${_genField('Nome Fantasia', e.nome_fantasia)}
        ${_genField('CNPJ', e.cnpj)}
        ${_genField('Inscrição Estadual', e.ie)}
        ${_genField('Tipo', e.tipo)}
        ${_genField('Ramo', e.ramo)}
        ${_genField('E-mail', e.email)}
        ${_genField('Telefone', e.telefone)}
        ${_genField('CEP', e.cep)}
      </div>
    `)}`;
}

function _genRender_curriculo() {
  const cv = _genCurriculo();
  const p = cv.pessoa;
  return `
    <div class="gen-top-bar">
      <h2>📋 Gerador de Currículo</h2>
      <button class="btn btn-primary" onclick="genActivate('curriculo')">↻ Gerar Novo</button>
    </div>
    <div class="gen-card gen-cv">
      <div class="gen-cv-header">
        <div class="gen-cv-name">${_esc(p.nome)}</div>
        <div class="gen-cv-contact">${_esc(p.email)} · ${_esc(p.telefone)} · ${_esc(p.cep)}</div>
      </div>
      <div class="gen-cv-section">
        <div class="gen-cv-section-title">💼 Experiência</div>
        ${cv.jobs.map(j=>`
          <div class="gen-cv-job">
            <div class="gen-cv-job-title">${_esc(j.cargo)} — ${_esc(j.empresa)}</div>
            <div class="gen-cv-job-period">${j.inicio} – ${j.fim}</div>
          </div>
        `).join('')}
      </div>
      <div class="gen-cv-section">
        <div class="gen-cv-section-title">🎓 Educação</div>
        <div class="gen-cv-job">
          <div class="gen-cv-job-title">${_esc(cv.edu.curso)} — ${_esc(cv.edu.instituicao)}</div>
          <div class="gen-cv-job-period">Conclusão: ${cv.edu.ano}</div>
        </div>
      </div>
      <div class="gen-cv-section">
        <div class="gen-cv-section-title">⚡ Habilidades</div>
        <div class="gen-cv-skills">${cv.skills.map(s=>`<span class="gen-cv-skill">${_esc(s)}</span>`).join('')}</div>
      </div>
    </div>`;
}

function _genRender_nome() {
  const batch = Array.from({length:8}, () => _genNome());
  return `
    <div class="gen-top-bar">
      <h2>✍️ Gerador de Nomes</h2>
      <button class="btn btn-primary" onclick="genActivate('nome')">↻ Gerar Lote</button>
    </div>
    ${_genCard('Nomes Gerados',`
      <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px">
        <button class="bbh-cat-pill active" onclick="genActivate('nome')">Todos</button>
        <button class="bbh-cat-pill" onclick="genRenderNomesFiltro('M')">Masculinos</button>
        <button class="bbh-cat-pill" onclick="genRenderNomesFiltro('F')">Femininos</button>
      </div>
      <div id="nomes-list">
        ${batch.map(n=>`
          <div class="gen-nome-row">
            <span class="gen-nome-badge ${n.sexo==='M'?'gen-badge-m':'gen-badge-f'}">${n.sexo}</span>
            <span>${_esc(n.nome)}</span>
            <button class="gen-copy-btn" onclick="genCopyText('${_esc(n.nome).replace(/'/g,"\\'")}')">📋</button>
          </div>
        `).join('')}
      </div>
    `)}`;
}

function genRenderNomesFiltro(sexo) {
  const list = document.getElementById('nomes-list');
  if(!list) return;
  const batch = Array.from({length:8}, () => _genNome(sexo));
  list.innerHTML = batch.map(n=>`
    <div class="gen-nome-row">
      <span class="gen-nome-badge ${n.sexo==='M'?'gen-badge-m':'gen-badge-f'}">${n.sexo}</span>
      <span>${_esc(n.nome)}</span>
      <button class="gen-copy-btn" onclick="genCopyText('${_esc(n.nome).replace(/'/g,"\\'")}')">📋</button>
    </div>
  `).join('');
}

function _genRender_nick() {
  const batch = Array.from({length:12}, () => _genNick());
  return `
    <div class="gen-top-bar">
      <h2>🎮 Gerador de Nicks</h2>
      <button class="btn btn-primary" onclick="genActivate('nick')">↻ Gerar Novo Lote</button>
    </div>
    ${_genCard('Nicks Gerados',`
      <div class="gen-nicks-grid" id="nicks-grid">
        ${batch.map(n=>`<div class="gen-nick-item" onclick="genCopyText('${n.replace(/'/g,"\\'")}');this.classList.add('gen-nick-copied');setTimeout(()=>this.classList.remove('gen-nick-copied'),1000)">${_esc(n)}</div>`).join('')}
      </div>
      <p style="color:var(--text3);font-size:.75rem;margin-top:8px">Clique para copiar</p>
    `)}`;
}

function _genRender_letras() {
  return `
    <div class="gen-top-bar">
      <h2>🔤 Gerador de Letras Diferentes</h2>
    </div>
    ${_genCard('Converta seu texto',`
      <textarea id="letras-input" class="gen-textarea" placeholder="Digite aqui seu texto..." oninput="genUpdateLetras()"
        rows="3">SCANTRELY</textarea>
      <div class="gen-letras-results" id="letras-output">
        ${_FONT_STYLES.map(s=>`
          <div class="gen-letras-row">
            <span class="gen-letras-style-name">${s.label}</span>
            <span class="gen-letras-preview" id="letras-${s.id}">${_esc(_toFontStyle('SCANTRELY', s.id))}</span>
            <button class="gen-copy-btn" onclick="genCopyText(document.getElementById('letras-${s.id}').textContent)">📋</button>
          </div>
        `).join('')}
      </div>
    `)}`;
}

function genUpdateLetras() {
  const text = document.getElementById('letras-input')?.value || '';
  _FONT_STYLES.forEach(s => {
    const el = document.getElementById(`letras-${s.id}`);
    if(el) el.textContent = _toFontStyle(text, s.id);
  });
}

function _genRender_simbolos() {
  return `
    <div class="gen-top-bar">
      <h2>✦ Símbolos para Copiar</h2>
    </div>
    <div id="simbolos-content">
      ${_SIMBOLOS_CATS.map(cat=>`
        <div class="gen-card" style="margin-bottom:12px">
          <div class="gen-card-hdr">${_esc(cat.cat)}</div>
          <div class="gen-simbolos-grid">
            ${cat.syms.map(s=>`<button class="gen-simbolo" title="Copiar ${s}" onclick="genCopyText('${s.replace(/'/g,"\\'")}');this.classList.add('copied');setTimeout(()=>this.classList.remove('copied'),600)">${s}</button>`).join('')}
          </div>
        </div>
      `).join('')}
    </div>`;
}

function _genRender_numeros() {
  const nums = _genNumeros(1, 100, 10, false);
  return `
    <div class="gen-top-bar">
      <h2>🔢 Gerador de Números Aleatórios</h2>
    </div>
    ${_genCard('Configurar',`
      <div class="gen-fields-row">
        <div><label>Mínimo</label><input type="number" id="num-min" value="1" class="gen-input"></div>
        <div><label>Máximo</label><input type="number" id="num-max" value="100" class="gen-input"></div>
        <div><label>Quantidade</label><input type="number" id="num-qty" value="10" min="1" max="1000" class="gen-input"></div>
      </div>
      <div style="display:flex;align-items:center;gap:10px;margin-top:10px">
        <input type="checkbox" id="num-unique"> <label for="num-unique">Sem repetição</label>
        <input type="checkbox" id="num-sort" checked> <label for="num-sort">Ordenar</label>
      </div>
      <button class="btn btn-primary" style="margin-top:12px" onclick="genGerarNumeros()">↻ Gerar</button>
    `)}
    ${_genCard('Resultado',`
      <div id="numeros-output" class="gen-number-output">${nums.join(', ')}</div>
      <button class="btn btn-secondary" style="margin-top:12px" onclick="genCopyText(document.getElementById('numeros-output').textContent)">📋 Copiar</button>
    `)}`;
}

function _genNumeros(min, max, qty, unique) {
  if(unique && (max-min+1) < qty) qty = max-min+1;
  let nums;
  if(unique) {
    const pool = Array.from({length:max-min+1}, (_,i)=>i+min);
    for(let i=pool.length-1;i>0;i--){const j=_rnd(0,i);[pool[i],pool[j]]=[pool[j],pool[i]];}
    nums = pool.slice(0,qty);
  } else {
    nums = Array.from({length:qty}, ()=>_rnd(min,max));
  }
  return nums.sort((a,b)=>a-b);
}

function genGerarNumeros() {
  const min = parseInt(document.getElementById('num-min')?.value || 1);
  const max = parseInt(document.getElementById('num-max')?.value || 100);
  const qty = Math.min(parseInt(document.getElementById('num-qty')?.value || 10), 1000);
  const unique = document.getElementById('num-unique')?.checked;
  const sort = document.getElementById('num-sort')?.checked;
  let nums = _genNumeros(min, max, qty, unique);
  if(!sort) nums = nums.sort(() => Math.random()-0.5);
  const out = document.getElementById('numeros-output');
  if(out) out.textContent = nums.join(', ');
}

function _genRender_senha() {
  const pw = _genSenha(16, true, true, true, true);
  return `
    <div class="gen-top-bar">
      <h2>🔑 Gerador de Senha</h2>
    </div>
    ${_genCard('Configurar',`
      <div class="gen-fields-row">
        <div><label>Comprimento</label><input type="number" id="pw-len" value="16" min="4" max="128" class="gen-input"></div>
      </div>
      <div class="gen-pw-opts">
        <label><input type="checkbox" id="pw-lower" checked> Minúsculas (a-z)</label>
        <label><input type="checkbox" id="pw-upper" checked> Maiúsculas (A-Z)</label>
        <label><input type="checkbox" id="pw-nums" checked> Números (0-9)</label>
        <label><input type="checkbox" id="pw-syms" checked> Símbolos (!@#$...)</label>
      </div>
      <button class="btn btn-primary" style="margin-top:12px" onclick="genGerarSenha()">↻ Gerar</button>
    `)}
    ${_genCard('Senha Gerada',`
      <div class="gen-number-big gen-senha-output" id="pw-output">${_esc(pw)}</div>
      <div style="display:flex;gap:8px;margin-top:12px">
        <button class="btn btn-secondary" onclick="genCopyText(document.getElementById('pw-output').textContent)">📋 Copiar</button>
        <button class="btn btn-secondary" onclick="genGerarSenha()">↻ Nova Senha</button>
      </div>
    `)}`;
}

function genGerarSenha() {
  const len = parseInt(document.getElementById('pw-len')?.value || 16);
  const lower = document.getElementById('pw-lower')?.checked ?? true;
  const upper = document.getElementById('pw-upper')?.checked ?? true;
  const nums  = document.getElementById('pw-nums')?.checked  ?? true;
  const syms  = document.getElementById('pw-syms')?.checked  ?? true;
  const el = document.getElementById('pw-output');
  if(el) el.textContent = _genSenha(len, lower, upper, nums, syms);
}

function _genRender_lorem() {
  const paras = _genLorem(2);
  return `
    <div class="gen-top-bar">
      <h2>📝 Gerador de Lorem Ipsum</h2>
    </div>
    ${_genCard('Configurar',`
      <div class="gen-fields-row">
        <div><label>Parágrafos</label><input type="number" id="lorem-p" value="2" min="1" max="20" class="gen-input"></div>
      </div>
      <div style="display:flex;gap:8px;margin-top:10px;flex-wrap:wrap">
        <button class="btn btn-primary" onclick="genGerarLorem()">↻ Gerar</button>
        <button class="btn btn-secondary" onclick="genCopyText(document.getElementById('lorem-output').textContent)">📋 Copiar Texto</button>
      </div>
    `)}
    ${_genCard('Texto Gerado',`<div id="lorem-output" class="gen-lorem-output">${paras.map(p=>`<p>${_esc(p)}</p>`).join('')}</div>`)}`;
}

function genGerarLorem() {
  const n = Math.min(parseInt(document.getElementById('lorem-p')?.value || 2), 20);
  const out = document.getElementById('lorem-output');
  if(out) out.innerHTML = _genLorem(n).map(p=>`<p>${_esc(p)}</p>`).join('');
}

function _genRender_imagem() {
  return `
    <div class="gen-top-bar">
      <h2>🖼️ Gerador de Imagem</h2>
    </div>
    ${_genCard('Configurar',`
      <div class="gen-fields-row">
        <div><label>Largura (px)</label><input type="number" id="img-w" value="640" class="gen-input"></div>
        <div><label>Altura (px)</label><input type="number" id="img-h" value="480" class="gen-input"></div>
        <div><label>Texto</label><input type="text" id="img-text" value="Placeholder" class="gen-input"></div>
      </div>
      <div class="gen-fields-row" style="margin-top:8px">
        <div><label>Cor Fundo</label><input type="color" id="img-bg" value="#1a2333" class="gen-input" style="height:34px"></div>
        <div><label>Cor Texto</label><input type="color" id="img-fg" value="#00c9a7" class="gen-input" style="height:34px"></div>
      </div>
      <button class="btn btn-primary" style="margin-top:12px" onclick="genGerarImagem()">↻ Gerar</button>
    `)}
    ${_genCard('Preview',`
      <img id="img-preview" src="https://placehold.co/640x480/1a2333/00c9a7?text=Placeholder" alt="placeholder" style="max-width:100%;border-radius:8px;border:1px solid var(--border)">
      <div style="margin-top:10px">
        <div id="img-url" style="font-size:.8rem;color:var(--text3);word-break:break-all;margin-bottom:8px">https://placehold.co/640x480/1a2333/00c9a7?text=Placeholder</div>
        <div style="display:flex;gap:8px">
          <button class="btn btn-secondary" onclick="genCopyText(document.getElementById('img-url').textContent)">📋 Copiar URL</button>
          <a id="img-download" href="https://placehold.co/640x480/1a2333/00c9a7?text=Placeholder" download="placeholder.png" class="btn btn-secondary" target="_blank">⬇ Baixar</a>
        </div>
      </div>
    `)}`;
}

function genGerarImagem() {
  const w = parseInt(document.getElementById('img-w')?.value || 640);
  const h = parseInt(document.getElementById('img-h')?.value || 480);
  const text = document.getElementById('img-text')?.value || 'Placeholder';
  const bg = (document.getElementById('img-bg')?.value || '#1a2333').replace('#','');
  const fg = (document.getElementById('img-fg')?.value || '#00c9a7').replace('#','');
  const url = `https://placehold.co/${w}x${h}/${bg}/${fg}?text=${encodeURIComponent(text)}`;
  const img = document.getElementById('img-preview');
  if(img) img.src = url;
  const urlEl = document.getElementById('img-url');
  if(urlEl) urlEl.textContent = url;
  const dl = document.getElementById('img-download');
  if(dl) dl.href = url;
}

function _genRender_sorteador() {
  return `
    <div class="gen-top-bar">
      <h2>🎲 Sorteador de Números</h2>
    </div>
    ${_genCard('Configurar Sorteio',`
      <div class="gen-fields-row">
        <div><label>De</label><input type="number" id="sort-min" value="1" class="gen-input"></div>
        <div><label>Até</label><input type="number" id="sort-max" value="60" class="gen-input"></div>
        <div><label>Quantos sortear</label><input type="number" id="sort-qty" value="6" min="1" max="100" class="gen-input"></div>
      </div>
      <button class="btn btn-primary" style="margin-top:12px" onclick="genSortear()">🎲 Sortear!</button>
    `)}
    ${_genCard('Resultado do Sorteio',`
      <div id="sort-result" class="gen-sort-result">
        <span style="color:var(--text3)">Clique em Sortear para começar</span>
      </div>
      <button class="btn btn-secondary" style="margin-top:12px;display:none" id="sort-copy-btn" onclick="genCopyText(document.getElementById('sort-result').dataset.nums||'')">📋 Copiar</button>
    `)}`;
}

function genSortear() {
  const min = parseInt(document.getElementById('sort-min')?.value || 1);
  const max = parseInt(document.getElementById('sort-max')?.value || 60);
  const qty = Math.min(parseInt(document.getElementById('sort-qty')?.value || 6), Math.min(100, max-min+1));
  const pool = Array.from({length:max-min+1}, (_,i)=>i+min);
  for(let i=pool.length-1;i>0;i--){const j=_rnd(0,i);[pool[i],pool[j]]=[pool[j],pool[i]];}
  const drawn = pool.slice(0,qty).sort((a,b)=>a-b);
  const out = document.getElementById('sort-result');
  if(out) {
    out.dataset.nums = drawn.join(', ');
    out.innerHTML = drawn.map(n=>`<span class="gen-sort-ball">${n}</span>`).join('');
  }
  const btn = document.getElementById('sort-copy-btn');
  if(btn) btn.style.display = '';
}

// ─── Event bindings per generator ────────────────────────────────────
function _genBindEvents(id) {
  // Most generators use inline onclick, but some need special bindings
  if(id === 'letras') genUpdateLetras();
}
