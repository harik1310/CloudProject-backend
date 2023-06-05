//to categorize the data that comes from the policy results table 
//into the desired categories
const SECTIONS = {
    "1":{
        default: 'Identity and Access Management'
    },
    "3": {
        '9':'Virtual Private cloud',
        default: "Logging & Monitoring",
    },
    '4':{
      default: 'Virtual Machines'
    },
    "5": {
        default: "Network Security",
        '4':'Security groups',
                
    },
    default: "Misc",
}


module.exports = {SECTIONS}
