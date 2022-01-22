import { Component, OnInit } from '@angular/core';
import { FormControl, FormGroup, Validators } from '@angular/forms';
import { CryptogyService } from '../services/cryptogy.service';
import { DomSanitizer } from '@angular/platform-browser';

@Component({
  selector: 'app-block',
  templateUrl: './block.component.html',
  styleUrls: ['./block.component.css']
})
export class BlockComponent implements OnInit {

  randomKeyLoading: boolean = false;
  errorRandomKey: boolean = false;

  encryptLoading: boolean = false;
  errorEncrypt: boolean = false;

  decryptLoading: boolean = false;
  errorDecrypt: boolean = false;

  imageLoading: boolean = false;
  errorImage: boolean = false;

  clearImage = null;
  cipherImage = null;

  form: FormGroup;
  key: string = "";
  invalidKey: boolean = false;
  constructor(private cryptoService: CryptogyService, private domSanitizer: DomSanitizer) { }

  ngOnInit(): void {
    this.form = new FormGroup({
      cipher: new FormControl("aes", { validators: Validators.required }),
      key: new FormControl(null, { validators: Validators.required }),
      cleartext: new FormControl(''),
      ciphertext: new FormControl(''),
      initialPermutation: new FormControl(""),
      schedule: new FormControl(""), 
      keyLength: new FormControl("16"), 
      encryptionMode: new FormControl("cbc"), 
      file: new FormControl(null), 
      decrypt_image: new FormControl(null)
    });
    this.generate_random_key();

    this.form.get("key").valueChanges.subscribe(val => {
       this.form.patchValue({"schedule": ""});
       this.form.patchValue({"initialPermutation": ""});
       this.form.updateValueAndValidity();
    });


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
      "0"
    )
      .subscribe(data => {
        //console.log(data);
        this.form.patchValue({"key": data["random_key"] })
        this.form.updateValueAndValidity();
        this.randomKeyLoading = false;
      }, err => {
        //console.log(err);
        if(err.error == "Invalid Key"){
          this.invalidKey = true;
        }
        this.errorRandomKey = true;
        this.randomKeyLoading = false;
      })
  }

  encrypt() {
    let values = this.form.value;
    
    //if(values.cipher == "aes"){
    //  if(values.key.length != parseInt(this.form.value.keyLength)){
    //      this.invalidKey = true;
    //      return;
    //  }
    //}


    this.form.patchValue({"schedule": ""});
    //this.form.patchValue({"initialPermutation": ""});
    this.form.updateValueAndValidity();

    this.invalidKey = false;
    this.encryptLoading = true;
    this.errorEncrypt = false;
    let cleartext = values.cleartext;
    this.invalidKey = false;

  
    this.cryptoService.encrypt(
      values.key,
      values.cipher,
      cleartext, 
      values.keyLength,
      "0",
      values.initialPermutation,
      values.schedule, 
      values.encryptionMode
    ).subscribe(
      data => {
        this.encryptLoading = false;
        this.form.patchValue({"ciphertext": data["ciphertext"] });
        this.form.updateValueAndValidity();
        if(data["permutation"]){
          this.form.patchValue({"initialPermutation": data["permutation"]});
          this.form.updateValueAndValidity();
        }
        if(data["schedule"]){
          this.form.patchValue({"schedule": data["schedule"]});
          this.form.updateValueAndValidity();
        }
        if(data["initialPermutation"]){
          console.log("initial");
          if(data["initialPermutation"] != this.form.value.initialPermutation){
              console.log("change")
              console.log(this.form.value.initialPermutation);
              console.log(data["initialPermutation"]);
              this.form.patchValue({"initialPermutation": data["initialPermutation"]});
              this.form.updateValueAndValidity();
          }
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
    this.cryptoService.encrypt_image(
      this.form.value.file, 
      this.form.value.cipher,
      this.form.value.key, 
      this.form.value.initialPermutation, 
      this.form.value.encryptionMode
    )
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
          //var file = new File([this.cipherImage], "encrypted_image");
          //console.log(file);
          var file = new File([data], "my_image.png", {type:"image/png", lastModified:new Date().getTime()})
          this.form.patchValue({"decrypt_image": file});
          this.form.updateValueAndValidity();
          console.log(this.form.value.decrypt_image);
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

    this.cryptoService.decrypt(
      values.key,
      values.cipher,
      ciphertext, 
      values.keyLength, 
      "0", 
      "0", 
      values.initialPermutation,
      values.schedule, 
      values.encryptionMode
    )
    .subscribe(
      data => {
        this.decryptLoading = false;
        this.form.patchValue({"cleartext": data["cleartext"]});
        this.form.updateValueAndValidity();
      }, err => {
        this.decryptLoading = false;
        this.errorDecrypt = true;
      }
    )
  }

  decrypt_image(){
    console.log("decrypt image!");
    console.log(this.form.value.decrypt_image);
    this.cryptoService.decrypt_image(
      this.form.value.decrypt_image, 
      this.form.value.cipher,
      this.form.value.key, 
      this.form.value.initialPermutation, 
      this.form.value.encryptionMode
    )
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

  onFileSelected2(event: any){
    const files = event.target.files;
    if (files.length === 0)
        return;

    const mimeType = files[0].type;
    if (mimeType.match(/image\/*/) == null) {
        return;
    }

    this.form.patchValue({decrypt_image: files[0]});
    this.form.updateValueAndValidity();

    console.log(files);
    console.log(files[0]);
    console.log(this.form.value.decrypt_image);

    const reader = new FileReader();
    reader.readAsDataURL(files[0]); 
    reader.onload = (_event) => { 
        this.cipherImage = reader.result; 
    }

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


  deleteCipherImage(){
    this.cipherImage = null;
  }

  deleteClearImage(){
    this.clearImage = null;
  }

}

