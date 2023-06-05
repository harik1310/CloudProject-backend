const express = require("express");
const router = express.Router();
const PDFdoucment = require('pdfkit');
const fs = require('fs');
const { Base64Encode } = require('base64-stream');
const axios = require('axios');

 
async function fetchData() {
    try {
      const response = await axios.get('http://localhost:8000/chart'); 
  
    const json = response.data;
  
    } catch (error) {
      console.error('Error fetching data:', error.message);
    }
  }
  fetchData();

function buildPDF(callback) {
    const doc = new PDFdoucment({ bufferPages: true, font: 'Times-Roman' });
    const stream = doc.pipe(new Base64Encode());

    // HEADER
    doc.fontSize(25)
        .text('Cloud Compliance Report', 100, 70);
    // HEADER

    // TABLE
    function generateTable(table, data) {
        doc.moveDown().fontSize(14).text(table.title, { align: 'center' });
        doc.moveDown().fontSize(12).text(table.subtitle, { align: 'center' });

        const tableTop = 150;
        const tableLeft = 100;
        const rowHeight = 30;
        const headerColor = "#000000";
        const alternateRowColor = "#f2f2f2";

        doc.lineWidth(1).strokeColor(headerColor);
        doc.font('Times-Bold');

        let currentTop = tableTop;
        let currentRow = 0;
        const headers = table.headers;

        doc.lineJoin('miter')
            .rect(tableLeft, currentTop, headers.length * 100, rowHeight)
            .stroke();

        headers.forEach(header => {
            doc.fillColor("#ffffff").text(header.label, tableLeft + header.width * currentRow, currentTop + 10, {
                width: header.width,
                align: 'center'
            });
            currentRow++;
        });

        currentTop += rowHeight;

        doc.font('Times-Roman');
        doc.fillColor("#000000");

        data.forEach((row, rowIndex) => {
            doc.save()
                .fillColor(rowIndex % 2 === 0 ? "#ffffff" : alternateRowColor)
                .rect(tableLeft, currentTop, headers.length * 100, rowHeight)
                .fill()
                .stroke();

            currentRow = 0;

            headers.forEach(header => {
                doc.text(row[header.property], tableLeft + header.width * currentRow, currentTop + 10, {
                    width: header.width,
                    align: 'center'
                });
                currentRow++;
            });

            currentTop += rowHeight;
        });

        //doc.restore();
    }

    const table = {
        title: "Title",
        subtitle: "Subtitle",
        headers: [
            { label: "Name", property: "name", width: 100 },
            { label: "Age", property: "age", width: 100 },
            { label: "Year", property: "year", width: 100 }
        ],
    };

    const data = [
        { name: "John Doe", age: 30, year: 1990 },
        { name: "Jane Smith", age: 25, year: 1995 },
        { name: "Bob Johnson", age: 35, year: 1985 }
    ];

    generateTable(table, data);
    // TABLE

    doc.end();
    doc.pipe(fs.createWriteStream('reportsdflka.pdf'))
    let val = "";
    stream.on('data', function (chunk) {
        val += chunk;
    });

    stream.on('end', function () {
        callback(`data:application/pdf;base64,${val}`);
    });
}

module.exports = { buildPDF };



