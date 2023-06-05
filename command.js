
const { spawn } = require("child_process");

const sync = spawn('bash', ['./shellScripts/resourceSync.sh']);

sync.stdout.on("data", data => {
    console.log(`stdout: ${data}`);
});

sync.stderr.on("data", data => {
    console.log(`stderr: ${data}`);
});

sync.on('error', (error) => {
    console.log(`error: ${error.message}`);
});

sync.on("close", code => {
    console.log(`child process exited with code ${code}`);
});
