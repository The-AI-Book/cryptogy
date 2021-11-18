import { Injectable } from "@angular/core";
import { Router } from "@angular/router";
import { Subject } from "rxjs";
import { environment } from "src/environments/environment";
import { HttpClient } from "@angular/common/http";
import { Encrypt } from "../models/encrypt.model";
import { Decrypt } from "../models/decrypt.model";
import { RandomKey } from "../models/random_key.model";
import { Analyze } from "../models/analyze.model";

@Injectable({ providedIn: 'root' })
export class CryptogyService {
    endpoint = environment.endpoint;
    constructor(private http: HttpClient, private router: Router) {}

    get_random_key(
        cipher: string,
        keyLength: string
    ){
        const RandomKey: RandomKey = {
           cipher: cipher,
           keyLength: keyLength
        }
        return this.http.post(this.endpoint + "/api/generate_random_key", RandomKey);
    }

    encrypt(
        key: string, 
        cipher: string, 
        cleartext: string,
        keyLength: string
    ){
        const EncryptData: Encrypt = {
            key: key,
            cipher: cipher, 
            cleartext: cleartext, 
            keyLength: keyLength
        }
        return this.http.post(this.endpoint + "/api/encrypt", EncryptData);
    }
    decrypt(
        key: string, 
        cipher: string, 
        ciphertext: string, 
        keyLength: string
    ){
        const DecryptData: Decrypt = {
            key: key, 
            cipher: cipher, 
            ciphertext: ciphertext, 
            keyLength: keyLength
        }
        return this.http.post(this.endpoint + "/api/decrypt", DecryptData);
    }
    analize(
        cipher: string,
        ciphertext: string
    ){
        const AnalyzeData: Analyze = {
            cipher: cipher, 
            ciphertext: ciphertext
        }
        return this.http.post(this.endpoint + "/api/analyze", AnalyzeData);
    }
}