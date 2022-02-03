import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { BlockComponent } from './block/block.component';
import { ClassicComponent } from './classic/classic.component';
import { GammaPentagonalComponent } from './gamma-pentagonal/gamma-pentagonal.component';
import { PublickeyComponent } from './publickey/publickey.component';
import { MainComponent } from './main/main.component';
import { DssComponent } from './dss/dss.component';

const routes: Routes = [
  {path: "", component: MainComponent}, 
  {path: "classic", component: ClassicComponent}, 
  {path: "block", component: BlockComponent}, 
  {path: "gamma-pentagonal", component: GammaPentagonalComponent },
  {path: "publickey", component : PublickeyComponent},
  {path: "dss", component: DssComponent}
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule]
})
export class AppRoutingModule { }
