const express = require("express");
const bcrypt = require("bcrypt");
const cors = require("cors");
const app = express();
const router = express.Router();
const { SECTIONS } = require('./sections.js')
const { client } = require("./database.js");
const { spawn } = require("child_process");
const report = require('./downloadreport.js')


app.use(cors());
app.use(express.json());
app.use(router);



// to sync all of the resources
app.post("/sync-resources", async (req, res) => {
  const sync = await spawn("bash", ["./shellScripts/resourceSync.sh"]);

  sync.stdout.on("data", (data) => {
    console.log(`stdout: ${data}`);
  });

  sync.stderr.on("data", (data) => {
    console.log(`stderr: ${data}`);
  });

  sync.on("error", (error) => {
    console.log(`error: ${error.message}`);
  });

  sync.on("close", (code) => {
    console.log(`child process exited with code ${code}`);
    res.sendStatus(200);
  });
});


// to sync the resources 
app.post("/shortsync-resources", async (req, res) => {
  const sync = await spawn("bash", ["./shellScripts/shortSync.sh"]);

  sync.stdout.on("data", (data) => {
    console.log(`stdout: ${data}`);
  });

  sync.stderr.on("data", (data) => {
    console.log(`stderr: ${data}`);
  });

  sync.on("error", (error) => {
    console.log(`error: ${error.message}`);
  });

  sync.on("close", (code) => {
    console.log(`child process exited with code ${code}`);
    res.sendStatus(200);
  });
});


// for downloading the report
router.get('/download-report', (req, res, next) => {
  let base64 = ""
  report.buildPDF(data => {
    base64 = data
    res.json({ base64 })
  })
})


//to get the list of the projects registered 
app.get('/getprojects', async (req, res) => {
  try {
    const projectList = await client.query(`SELECT * FROM app_project_form;`)
    res.json(projectList)
  } catch (error) {
    console.log(error)
  }
})


//get the data for the donut chart
app.get("/chart", async (req, res) => {
  try {
    const pass = await client.query(`
        SELECT * FROM aws_policy_results UNION SELECT * FROM gcp_policy_results UNION SELECT * FROM azure_policy_results;
    `);

    const rows = pass.rows

    for (let row of rows) {
      const [check_id_rounded, check_id_after_decimal] = row.check_id.split(".")

      // 5 not in SECTIONS,
      // row.section = SECTIONS["default"]
      if (!(check_id_rounded in SECTIONS)) {
        row.section = SECTIONS["default"]
        continue
      }


      // 1 not in SECTIONS[5] (5.1)
      // row.section = SECTIONS[5]["default"
      if (!(check_id_after_decimal in SECTIONS[check_id_rounded])) {
        row.section = SECTIONS[check_id_rounded]["default"]
        continue
      }

      // SECTIONS[5][1]
      row.section = SECTIONS[check_id_rounded][check_id_after_decimal]
    }

    res.json(pass);
  } catch (err) {
    console.log(err);
  }
});

// for the progress bar
app.get("/chart/aws", async (req, res) => {
  try {
    const fail = await client.query(`SELECT * FROM aws_policy_results;`);
    res.json(fail);
  } catch (err) {
    console.log(err);
  }
});

// for the progress bar
app.get("/chart/gcp", async (req, res) => {
  try {
    const fail = await client.query(`SELECT * FROM gcp_policy_results;`);
    res.json(fail);
  } catch (err) {
    console.log(err);
  }
});

// for the progress bar
app.get("/chart/azure", async (req, res) => {
  try {
    const data = await client.query(`SELECT * FROM azure_policy_results;`);
    res.json(data);
  } catch (err) {
    console.log(err);
  }
});

//receive the data from the frontend for the project details
app.post('/api/projects', async (req, res) => {
  try {
    const { projectName,
      awsResourceId,
      gcpResourceId,
      azureResourceId,
      projectDescription } = req.body;

    const query = `INSERT INTO app_project_form (project_name, aws_resource_id, gcp_resource_id, azure_resource_id,project_description) VALUES ($1, $2, $3, $4, $5)`

    await client.query(query, [projectName, awsResourceId, gcpResourceId, azureResourceId, projectDescription]);

    res.status(200).json({ message: 'Form data inserted successfully' });
  } catch (error) {
    console.log('Error inserting form data:', error);
    res.status(500).json({ error: 'An error occurred while inserting form data' });
  }
});


//get a list of attack tactics , the webscraped data
app.get("/attackpatterns", async (req, res) => {
  try {
    const fail = await client.query(`SELECT DISTINCT pr.check_id, pr.title, pr.subscription_id, pr.status, ac.id, ac.techniques, ac.tactics, ac.mitigations
    FROM (
        SELECT check_id, title, subscription_id, status FROM azure_policy_results
        UNION ALL
        SELECT check_id, title, resource_id, status FROM gcp_policy_results
        UNION ALL 
        SELECT check_id, title, resource_id, status FROM aws_policy_results
    ) AS pr
    JOIN aws_controls AS ac ON pr.check_id = ac.id ORDER BY pr.check_id;;`);
    res.json(fail);
  } catch (err) {
    console.log(err);
  }
});


  app.get('/bardapi', async (req, res) => {

    var dataToSend;
    // spawn new child process to call the python script
    const pythonProcess = await spawn('python3', ['bard.py']);
    let response = '';
    pythonProcess.stdout.on('data', (data) => {
      response += data;
    });

    // Capture any errors that occur during execution
    pythonProcess.stderr.on('data', (data) => {
      console.error(`Error executing bard.py script: ${data}`);
    });

    // Handle the completion of the bard.py script
    pythonProcess.on('close', (code) => {
      if (code === 0) {
        const jsonData = JSON.parse(response);
        console.log(jsonData);
        res.json(jsonData)
        // Use the jsonData as needed in your Node.js code
      } else {
        console.error(`bard.py script finished with non-zero exit code ${code}`);
      }
    })
  })


app.get('/getthreatpattern', async (req, res) => {

  try {
    const threatData = await client.query(`SELECT DISTINCT controls.id, controls.section, controls.context, controls.techniques, controls.tactics, controls.mitigations,
    attack_techniques.description AS technique_desc,
    CASE
        WHEN controls.source = 'aws_controls' THEN 'AWS'
        WHEN controls.source = 'gcp_controls' THEN 'GCP'
        WHEN controls.source = 'azure_controls' THEN 'Azure'
        ELSE 'Unknown'
    END AS source, attack_mitigations.description,
    policy_results.status, attack_tactics.tactic_name, attack_tactics.tactic_description 
	FROM (
    SELECT id, section, context, techniques, tactics, mitigations, 'aws_controls' AS source FROM aws_controls
    UNION
    SELECT id, section, context, techniques, tactics, mitigations, 'gcp_controls' AS source FROM gcp_controls
    UNION
    SELECT id, section, context, techniques, tactics, mitigations, 'azure_controls' AS source FROM azure_controls
) AS controls
LEFT JOIN attack_techniques ON controls.techniques LIKE 'T%' AND attack_techniques.technique_id = controls.techniques
LEFT JOIN attack_tactics ON controls.tactics = attack_tactics.tactic_id
JOIN attack_mitigations ON controls.mitigations = attack_mitigations.mitigation_id
JOIN (
    SELECT check_id, resource_id, status, 'gcp' AS source FROM gcp_policy_results
    UNION ALL
    SELECT check_id, resource_id, status, 'aws' AS source FROM aws_policy_results
    UNION ALL
    SELECT check_id, resource_id, status, 'azure' AS source FROM azure_policy_results
) AS policy_results ON controls.id = policy_results.check_id
WHERE attack_techniques.technique_id LIKE 'T%'
ORDER BY controls.id;`)
        res.json(threatData)
  } catch (error) {
      console.log(error)
  }
  

}
)

app.listen(8000, () => {
  console.log("listening on 8000");
});


// SELECT DISTINCT controls.id, controls.section, controls.context, controls.techniques, controls.mitigations,
//     CASE
//         WHEN controls.source = 'aws_controls' THEN 'AWS'
//         WHEN controls.source = 'gcp_controls' THEN 'GCP'
//         WHEN controls.source = 'azure_controls' THEN 'Azure'
//         ELSE 'Unknown'
//     END AS source, attack_mitigations.description,
//     policy_results.status
// FROM (
//     SELECT id, section, context, techniques, mitigations, 'aws_controls' AS source FROM aws_controls
//     UNION
//     SELECT id, section, context, techniques, mitigations, 'gcp_controls' AS source FROM gcp_controls
//     UNION
//     SELECT id, section, context, techniques, mitigations, 'azure_controls' AS source FROM azure_controls
// ) AS controls
// LEFT JOIN attack_techniques ON controls.techniques LIKE 'T%'
// JOIN attack_mitigations ON controls.mitigations = attack_mitigations.mitigation_id
// JOIN (
//     SELECT check_id,resource_id, status, 'gcp' AS source FROM gcp_policy_results
//     UNION ALL
//     SELECT check_id,resource_id, status, 'aws' AS source FROM aws_policy_results
//     UNION ALL
//     SELECT check_id,resource_id, status, 'azure' AS source FROM azure_policy_results
// ) AS policy_results ON controls.id = policy_results.check_id
// WHERE attack_techniques.technique_id LIKE 'T%'
// ORDER BY controls.id;