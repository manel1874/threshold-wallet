import os
import subprocess
import signal
import time
from flask import Flask, render_template, request

app = Flask(__name__)


@app.route('/')
def welcomePage():
    return render_template("index.html")



@app.route('/run_keygen/', methods=["POST", "GET"])
def run_keygen():
    if request.method == "POST":
        nOfPart = request.form["nOfPart"]
        t = request.form["t"]
        
        path = "../multi-party-ecdsa/target/release/examples"
        
        processes = []

        # Run the manager
        cmd_managment = path+"/gg20_sm_manager"
        mng_process = subprocess.Popen("exec " + cmd_managment, shell=True, preexec_fn=os.setsid)
        time.sleep(1)
        #processes.append(mng_process)

        for i in range(int(nOfPart)):
            cmd_party_i = path+"/gg20_keygen -t "+t+" -n "+nOfPart+" -i "+str(i+1)+" --output local-share"+str(i+1)+".json"
            process = subprocess.Popen(cmd_party_i, shell=True)
            time.sleep(1)
            processes.append(process)

        output = [p.wait() for p in processes]
        mng_process.kill()
        
        #output = [p.wait() for p in processes]

        #print(output)

        yay = "yay"

        return render_template("keygen_result.html", tree=yay)
    else:
        return render_template("keygen.html")




@app.route('/run_sign/', methods=["POST", "GET"])
def run_sign():
    if request.method == "POST":
        id = request.form["partyId"]
        nOfSeq = request.form["nOfSeq"]
        
        """
        Run SMC
        """
        cmd = './runUPGMA ' + id + ' ' + nOfSeq
        os.system(cmd)

        tree_raw = open("phylogeneticTree/upgma_tree.nwk", "r")
        tree_file = tree_raw.read()

        return render_template("smcComplete.html", tree=tree_file)
    else:
        return render_template("sign.html")



@app.route('/runUPGMA')
def runUPGMA():

    cmd = './runUPGMA 0 2'
    os.system(cmd)

    return "Computing..."




if __name__ == '__main__':
    app.run(debug=True)