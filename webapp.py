import os
import subprocess
import time
import ast
import aux
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

        # Run each party
        for i in range(int(nOfPart)):
            cmd_party_i = path+"/gg20_keygen -t "+t+" -n "+nOfPart+" -i "+str(i+1)+" --output sks/local-share"+str(i+1)+".json"
            process = subprocess.Popen(cmd_party_i, shell=True)
            time.sleep(1)
            processes.append(process)

        # Wait for all the processes to finish
        output = [p.wait() for p in processes]

        # Kill the manager process to avoid conflicts for other interactions
        mng_process.kill()

        # Get public key
        _ , pk = aux.getPK(int(nOfPart))

        # Get wallet address
        addr = aux.pkToAddr(pk)

        return render_template("keygen_result.html", nOfShares=nOfPart, threshold=t, publicKey=pk, address=addr)
    else:
        return render_template("keygen.html")


@app.route('/run_sign/', methods=["POST", "GET"])
def run_sign():
    if request.method == "POST":
        sks = request.form["sks"]
        msg = request.form["msg"]

        path = "../multi-party-ecdsa/target/release/examples"
        
        processes = []

        # Run the manager
        cmd_managment = path+"/gg20_sm_manager"
        mng_process = subprocess.Popen("exec " + cmd_managment, shell=True, preexec_fn=os.setsid)
        time.sleep(1)
        
        sks_list = ast.literal_eval("["+sks+"]")

        for i in sks_list:
            cmd_party_i = path+"/gg20_signing -p "+sks+" -d "+msg+" -l sks/local-share"+str(i)+".json > signature/signature"+str(i)+".json"
            process = subprocess.Popen(cmd_party_i, shell=True)
            time.sleep(1)
            processes.append(process)

        output = [p.wait() for p in processes]
        mng_process.kill()

        signature = aux.getSign()

        return render_template("sign_result.html", sign=signature, msg=msg)
    else:
        return render_template("sign.html")



if __name__ == '__main__':
    app.run(debug=True)