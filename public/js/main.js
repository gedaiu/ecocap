var socket;

function getReport() {
  socket.send(JSON.stringify({ "name": "report" }));
}

function connect() {
  socket = new WebSocket("ws://localhost:8880/ws");

  socket.onopen = function(event) {
    getReport();
  }

  socket.onclose = function(event) {
    setTimeout(function() {
      connect();
    }, 2000);
  }

  socket.onmessage = function(event) {
    interpretData(JSON.parse(event.data));

    setTimeout(getReport, 2000);
  }
}

function parseTraficData(data, factor) {
  let result = [];
  let max = 0;
  let size = parseInt(data.length / 400);

  data.forEach((value, index) => {
    result[parseInt(index / size)] = result[parseInt(index / size)] + value || value;
  });

  result.forEach((value, index) => {
    result[index] *= factor;
  });

  return result;
}

function interpretData(data) {
  console.log(data);

  let download = parseTraficData(data.download, 0.1024);
  let upload = parseTraficData(data.upload, 0.1024);

  new Chartist.Line('.ct-chart', {
    series: [
      download,
      upload,
    ]
  }, {
    showArea: true,
    showLine: true,
    showPoint: false,
    fullWidth: true,
    axisX: {
      showLabel: false,
      showGrid: false
    }
  });
}

$(function() {
  connect();
});
