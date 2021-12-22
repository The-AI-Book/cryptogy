import { Component, OnInit } from '@angular/core';
import { FormControl, FormGroup, Validators } from '@angular/forms';
import { CryptogyService } from '../services/cryptogy.service';
import { DomSanitizer } from '@angular/platform-browser';
@Component({
  selector: 'app-classic',
  templateUrl: './classic.component.html',
  styleUrls: ['./classic.component.css']
})
export class ClassicComponent implements OnInit {

  randomKeyLoading: boolean = false;
  errorRandomKey: boolean = false;

  partitionError: boolean = false;

  encryptLoading: boolean = false;
  errorEncrypt: boolean = false;

  decryptLoading: boolean = false;
  errorDecrypt: boolean = false;

  analyzeLoading: boolean = false;
  errorAnalyze: boolean = false;
  errorAnalyzeMessage: string = "";

  imageLoading: boolean = false;
  errorImage: boolean = false;
  clearImage = null;
  cipherImage = null;

  form: FormGroup;
  key: string = "";
  invalidKey: boolean = false;

  dummyClearText: string = "thealmondtreewasintentativeblossomthedayswerelongeroftenendingwithmagnificenteveningsofcorrugatedpinkskiesthehuntingseasonwasoverwithhoundsandgunsputawayforsixmonthsthevineyardswerebusyagainasthewellorganizedqarmerstreatedtheirvinesandthemorelackadaisicalneighborshurriedtodothepruningtheyshouldhavedoneinnovember"
  dummyCipherText: string = "";
  lonDummy: number = this.dummyClearText.length;

  constructor(private cryptoService: CryptogyService, private domSanitizer: DomSanitizer) { }

  ngOnInit(): void {

    this.form = new FormGroup({
      cipher: new FormControl("shift", { validators: Validators.required }),
      keyLength: new FormControl(5),
      key: new FormControl(null, { validators: Validators.required }),
      cleartext: new FormControl(''),
      ciphertext: new FormControl(''),
      keyStream: new FormControl(''), 
      numPartitions: new FormControl(2, {validators: Validators.required}), 
      file: new FormControl(null)
    });
    this.generate_random_key();
  }

  cryptosystem_change() {
    this.generate_random_key();
    this.form.patchValue({"cleartext": ""});
    this.form.patchValue({"ciphertext": ""}); 
    this.form.updateValueAndValidity();
  }

  generate_random_key() {
    this.invalidKey = false;
    this.randomKeyLoading = true;
    this.errorRandomKey = false;
    let values = this.form.value;
    this.cryptoService.get_random_key(
      values.cipher,
      values.keyLength, 
      values.numPartitions
    ).subscribe(
      data => {
        //console.log(data);
        this.form.patchValue({"key": data["random_key"] })
        this.form.updateValueAndValidity();
        this.randomKeyLoading = false;
      },
      err => {
        //console.log(err);
        if(err.error == "Invalid Key"){
          this.invalidKey = true;
        }
        this.errorRandomKey = true;
        this.randomKeyLoading = false;
    })
  }

  encrypt() {

    this.invalidKey = false;
    let values = this.form.value;
    this.encryptLoading = true;
    this.errorEncrypt = false;

    let cleartext = values.cleartext;
    if (this.form.value.cipher == "vigenere"){
      cleartext = this.dummyClearText + cleartext;
      //console.log("Cleartext sent to the backend: ", cleartext)
    }

    this.cryptoService.encrypt(
      values.key,
      values.cipher,
      cleartext, 
      values.keyLength, 
      values.numPartitions, 
    ).subscribe(
      data => {
        this.encryptLoading = false;
        if (this.form.value.cipher == "vigenere"){
          this.dummyCipherText = data["ciphertext"].substring(0, this.lonDummy);
          data["ciphertext"] = data["ciphertext"].substring(this.lonDummy, data["ciphertext"].length);
        }
        this.form.patchValue({"ciphertext": data["ciphertext"] });
        this.form.updateValueAndValidity();
        if(data["key_stream"]){
          this.form.patchValue({"keyStream": data["key_stream"]});
          this.form.updateValueAndValidity();
        }
      }, err => {
        if(err.error == "Invalid Key"){
          this.invalidKey = true;
        }
        this.encryptLoading = false;
        this.errorEncrypt = true;
      }
    )
  }

  encrypt_image(){
    //console.log("encrypt image!");
    this.cryptoService.encrypt_image(this.form.value.file)
    .subscribe(
      data => {
        //console.log(data);
        //console.log("Loading image!");
        const reader = new FileReader();
        reader.readAsDataURL(new Blob([<any> data]));
        reader.onload = (e) => {

          let url = e.target.result as string;
          let secureUrl = this.domSanitizer.bypassSecurityTrustResourceUrl(
            url
          );
          this.cipherImage = secureUrl;
          //console.log(this.cipherImage);
        }
      }, 
      err => {
        console.log(err);
      }
    )
  }

  decrypt() {
    let values = this.form.value;
    this.decryptLoading = true;
    this.errorDecrypt = false;

    let ciphertext = values.ciphertext;
    if (this.form.value.cipher == "vigenere"){
       ciphertext = this.dummyCipherText + ciphertext;
       //console.log("Ciphertext sent to backend: ", ciphertext);
    }

    this.cryptoService.decrypt(
      values.key,
      values.cipher,
      ciphertext, 
      values.keyLength, 
      values.keyStream, 
      values.numPartitions
    ).subscribe(
      data => {
        this.decryptLoading = false;
        if (this.form.value.cipher == "vigenere"){
          data["cleartext"] = data["cleartext"].substring(this.lonDummy, data["cleartext"].length);
        }
        this.form.patchValue({"cleartext": data["cleartext"]});
        this.form.updateValueAndValidity();
      }, err => {
        this.decryptLoading = false;
        this.errorDecrypt = true;
      }
    )
  }

  decrypt_image(){
    //console.log("decrypt image!");
    this.cryptoService.decrypt_image()
    .subscribe(
      data => {
        //console.log(data);
        //console.log("Loading image!");
        const reader = new FileReader();
        reader.readAsDataURL(new Blob([<any> data]));
        reader.onload = (e) => {
          let url = e.target.result as string;
          let secureUrl = this.domSanitizer.bypassSecurityTrustResourceUrl(
            url
          );
          this.clearImage = secureUrl;
          //console.log(this.clearImage);
        }
      }, 
      err => {
        console.log(err);
      }
    )
  }

  clearText(){
    this.form.patchValue({"cleartext":""})
    this.form.updateValueAndValidity();
  }

  clearCipherText(){
    this.form.patchValue({"ciphertext":""})
    this.form.updateValueAndValidity();
  }

  analyze() { 
    let values = this.form.value;
    this.analyzeLoading = true;
    this.errorAnalyze = false;
    this.form.controls["keyStream"].enable();

    let ciphertext = values.ciphertext;
    if (this.form.value.cipher == "vigenere"){
       ciphertext = this.dummyCipherText + ciphertext;
      //console.log("Ciphertext sent to backend: ", ciphertext);
    }

    this.cryptoService.analize(
      values.cipher, 
      ciphertext, 
      values.cleartext,
      values.numPartitions
    ).subscribe(
      data => {
        this.analyzeLoading = false;
        this.form.patchValue({"cleartext": data["cleartext"]});
        this.form.updateValueAndValidity();
      }, 
      err => {
        //console.log(err);
        this.errorAnalyzeMessage = err.error.error;
        this.errorAnalyze = true;
        this.analyzeLoading = false;
      }
    )
    this.form.controls["keyStream"].disable();
  }

  onFileSelected(event: any){
    const files = event.target.files;
    if (files.length === 0)
        return;

    const mimeType = files[0].type;
    if (mimeType.match(/image\/*/) == null) {
        return;
    }

    this.form.patchValue({file: files[0]});
    this.form.updateValueAndValidity();

    //console.log(files);
    //console.log(files[0]);
    //console.log(this.form.value.file);

    const reader = new FileReader();
    reader.readAsDataURL(files[0]); 
    reader.onload = (_event) => { 
        this.clearImage = reader.result; 
    }
  }

}
