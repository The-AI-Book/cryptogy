import { Injectable } from "@angular/core";
import { Router } from "@angular/router";
import { Subject } from "rxjs";
import { environment } from "src/environments/environment";
import { HttpClient, HttpHeaders } from "@angular/common/http";
import { Crypto } from "../models/crypto.model";

@Injectable({ providedIn: 'root' })
export class CryptogyService {
    endpoint = environment.endpoint;
    constructor(private http: HttpClient, private router: Router) {}

    get_random_key(
        cipher: string,
        keyLength: string, 
        numPartitions: string
    ){
        const CryptoData: Crypto = {
           cipher: cipher,
           keyLength: keyLength,
           key: "",
           cleartext: "",
           ciphertext: "",
           keyStream: "", 
           numPartitions: numPartitions, 
           initialPermutation: "",
           schedule: "",
           encryptionMode: ""
        }
        //console.log(this.endpoint + "/api/generate_random_key");
        return this.http.post(this.endpoint + "/api/generate_random_key", CryptoData);
    }

    encrypt(
        key: string, 
        cipher: string, 
        cleartext: string,
        keyLength: string, 
        numPartitions: string, 
        initialPermutation: string,
        schedule: string, 
        encryptionMode: string
    ){

        const CryptoData: Crypto = {
            key: key,
            cipher: cipher, 
            cleartext: cleartext, 
            keyLength: keyLength, 
            ciphertext: "", 
            keyStream: "", 
            numPartitions: numPartitions, 
            initialPermutation: initialPermutation,
            schedule: schedule, 
            encryptionMode: encryptionMode
        }
        console.log(CryptoData);
        return this.http.post(this.endpoint + "/api/encrypt", CryptoData);
    }

    encrypt_image(
        file: File, 
        cipher: string, 
        key: string, 
        initialPermutation: string, 
        encryptionMode: string
    ){
        console.log(file);
        const data = new FormData();
        data.append("cipher", cipher);
        data.append("key", key);
        data.append("initialPermutation", initialPermutation);
        data.append("encryptionMode", encryptionMode);
        data.append("files", file, file.name);
        console.log(data);
        return this.http.post(this.endpoint + "/api/encrypt_image", data, {responseType: "blob"})
    }

    decrypt_image(
        file: File, 
        cipher: string, 
        key: string, 
        initialPermutation: string, 
        encryptionMode: string
    ){
        console.log(file);
        const data = new FormData();
        data.append("cipher", cipher);
        data.append("key", key);
        data.append("initialPermutation", initialPermutation);
        data.append("encryptionMode", encryptionMode);
        data.append("files", file, file.name);
        console.log(data);
        return this.http.post(this.endpoint + "/api/decrypt_image", data, {responseType: "blob"})
    }

    decrypt(
        key: string, 
        cipher: string, 
        ciphertext: string, 
        keyLength: string, 
        keyStream: string, 
        numPartitions: string, 
        initialPermutation: string,
        schedule: string,
        encryptionMode: string
    ){
        const CryptoData: Crypto = {
            key: key, 
            cipher: cipher, 
            ciphertext: ciphertext, 
            keyLength: keyLength, 
            keyStream: keyStream, 
            cleartext: "", 
            numPartitions: numPartitions, 
            initialPermutation: initialPermutation,
            schedule: schedule,
            encryptionMode: encryptionMode
        }
        console.log(CryptoData);
        return this.http.post(this.endpoint + "/api/decrypt", CryptoData);
    }

    analize(
        cipher: string,
        ciphertext: string,
        cleartext: string, 
        numPartitions: string,
    ){
        const CryptoData: Crypto = {
            cipher: cipher, 
            ciphertext: ciphertext, 
            cleartext: cleartext,
            keyStream: "", 
            key: "", 
            keyLength: "", 
            numPartitions: numPartitions, 
            initialPermutation: "",
            schedule: "", 
            encryptionMode: ""
        }
        return this.http.post(this.endpoint + "/api/analyze", CryptoData);
    }

    change_graph(
        cipher: string, 
        key: string, 
    ){
        console.log("service change")
        const data = new FormData();
        data.append("cipher", cipher);
        data.append("key", key);
        console.log(data);
        return this.http.post(this.endpoint + "/api/change_graph", data);
    }


    show_graph(
        cipher: string, 
        key: string, 
    ){
        const data = new FormData();
        data.append("cipher", cipher);
        data.append("key", key);
        console.log(data);
        return this.http.post(this.endpoint + "/api/show_graph", data, {responseType: "blob"});
    }

}