import { Component, OnInit } from '@angular/core';
import { FormControl, FormGroup, Validators } from '@angular/forms';
import { DomSanitizer } from '@angular/platform-browser';
import { CryptogyService } from '../services/cryptogy.service';

@Component({
  selector: 'app-dss',
  templateUrl: './dss.component.html',
  styleUrls: ['./dss.component.css']
})
export class DssComponent implements OnInit {

  randomKeyLoading: boolean = false;
  errorRandomKey: boolean = false;

  encryptLoading: boolean = false;
  errorEncrypt: boolean = false;

  decryptLoading: boolean = false;
  errorDecrypt: boolean = false;

  form: FormGroup;
  key: string = "";
  invalidKey: boolean = false;
  constructor(private cryptoService: CryptogyService, private domSanitizer: DomSanitizer) { }

  ngOnInit(): void {
    this.form = new FormGroup({
      cleartext: new FormControl("", {validators: Validators.required }),
      signature: new FormControl("")
    });
  }

  encrypt() {
    let values = this.form.value;
    this.encryptLoading = true;
    this.errorEncrypt = false;
    let cleartext = values.cleartext;

    this.cryptoService.signature(
      cleartext
    )
    .subscribe(
      data => {
        this.encryptLoading = false;
        this.form.patchValue({"signature": data["signature"] });
        this.form.updateValueAndValidity();

      }, err => {
        this.encryptLoading = false;
        this.errorEncrypt = true;
      }
    )
  }


  clearText(){
    this.form.patchValue({"cleartext":""})
    this.form.updateValueAndValidity();
  }

}
