var sys = require('sys')
var exec = require('child_process').exec;

function puts(error, stdout, stderr) { sys.puts(stdout) }
exec('docker exec -w "/root/libest" -e "LD_LIBRARY_PATH=/usr/local/pqpki-openssl1.0.2o/lib" -e "PATH=/usr/local/pqpki-openssl1.0.2o/bin:$PATH" cli bash validate > output.txt', function(err, stdout, stderr) {
  console.log(stdout);
});
