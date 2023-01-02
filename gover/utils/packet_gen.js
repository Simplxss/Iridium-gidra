const { execSync } = require('child_process');
const { writeFileSync, existsSync, readdirSync, readFileSync, unlinkSync, mkdirSync } = require('fs');
const path = require('path');
const { exit } = require('process');

const rootDir = path.join(__dirname, '..');
const protoDir = path.join(rootDir, 'proto');
const protoGenDir = path.join(rootDir, 'gen');
const sorapointaDir = path.join(rootDir, '..', 'thirdparty', 'Sorapointa-Protos', 'proto');

const header = [
    'package utils',
    '',
    'import (',
    '	"github.com/MoonlightPS/Iridium-gidra/gover/gen"',
    ')',
    '',
    'var protoMap = map[int]Message{}',
    '',
    'const ('
];

const body = [
    ')',
    '',
    'func init() {',
];

const footer = [
    '}',
    '',
];

const reg = /\/\/   CMD_ID = \d+;/
const ids = {};

if (!existsSync(protoDir)) {
    mkdirSync(protoDir);
}


for (const fileName of readdirSync(protoGenDir)) {
    unlinkSync(path.join(protoGenDir, fileName)); // remove existed generated protos
}
for (const fileName of readdirSync(protoDir)) {
    unlinkSync(path.join(protoDir, fileName)); // remove existed protos
}

for (const fileName of readdirSync(sorapointaDir)) {
    // copy proto from sorapointa
    const proto = fileName.slice(0, -6);
    const content = readFileSync(path.join(sorapointaDir, fileName)).toString()
        .replace("option java_package = \"org.sorapointa.proto\";", "option go_package = \"/gen\";");
    writeFileSync(path.join(protoDir, fileName), content);

    const cmd = reg.exec(content)?.[0];
    if (!cmd) continue;
    ids[cmd.split(' ').pop()] = proto;
}

for (const key in ids) {
    const type = ids[key];
    header.push(`	${type} = ${key}`)
    body.push(`	protoMap[${type}] = &gen.${type}{}`);
}

execSync([
    "protoc",
    `-I=${protoDir}`,
    `--go_out=${rootDir}`,
    `--proto_path=${rootDir}`,
    `${protoDir}\\*.proto`
].join(' '));

writeFileSync(path.join(__dirname, 'packet_gen.go'), header.concat(body, footer).join('\n'));