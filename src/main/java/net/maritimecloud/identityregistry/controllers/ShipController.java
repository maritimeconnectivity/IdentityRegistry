/* Copyright 2015 Danish Maritime Authority.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package net.maritimecloud.identityregistry.controllers;

import org.springframework.web.bind.annotation.RestController;

import net.maritimecloud.identityregistry.model.Certificate;
import net.maritimecloud.identityregistry.model.Organization;
import net.maritimecloud.identityregistry.model.Ship;
import net.maritimecloud.identityregistry.model.ShipAttribute;
import net.maritimecloud.identityregistry.services.ShipService;

import java.util.ArrayList;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;

@RestController
@RequestMapping(value={"admin", "oidc", "x509"})
public class ShipController {
    private ShipService shipService;

    @Autowired
    public void setShipService(ShipService organizationService) {
        this.shipService = organizationService;
    }

    /**
     * Creates a new Ship
     * 
     * @return a reply...
     */
    @RequestMapping(
            value = "/api/ship",
            method = RequestMethod.POST,
            produces = "application/json;charset=UTF-8")
    @ResponseBody
    public ResponseEntity<?> createShip(HttpServletRequest request, @RequestBody Ship input) {
        Ship newShip = this.shipService.saveShip(input);
        return new ResponseEntity<Ship>(newShip, HttpStatus.OK);
    }

    /**
     * Returns info about the ship identified by the given ID
     * 
     * @return a reply...
     */
    @RequestMapping(
            value = "/api/ship/{shipId}",
            method = RequestMethod.GET,
            produces = "application/json;charset=UTF-8")
    @ResponseBody
    public ResponseEntity<?> getShip(HttpServletRequest request, @PathVariable Long shipId) {
        Ship ship = this.shipService.getShipById(shipId);
        return new ResponseEntity<Ship>(ship, HttpStatus.OK);
    }

    /**
     * Updates a Ship
     * 
     * @return a reply...
     */
    @RequestMapping(
            value = "/api/ship/{shipId}",
            method = RequestMethod.PUT)
    @ResponseBody
    public ResponseEntity<?> updateShip(HttpServletRequest request, @PathVariable Long shipId, @RequestBody Ship input) {
        Ship ship = this.shipService.getShipById(shipId);
        if (ship != null && ship.getId() == input.getId()) {
            input.copyTo(ship);
            this.shipService.saveShip(ship);
            return new ResponseEntity<>(HttpStatus.OK);
        }
        return new ResponseEntity<>(HttpStatus.NOT_FOUND);
    }

    /**
     * Deletes a Ship
     * 
     * @return a reply...
     */
    @RequestMapping(
            value = "/api/ship/{shipId}",
            method = RequestMethod.DELETE)
    @ResponseBody
    public ResponseEntity<?> deleteShip(HttpServletRequest request, @PathVariable Long shipId) {
        Ship ship = this.shipService.getShipById(shipId);
        if (ship != null) {
            this.shipService.deleteShip(shipId);
            return new ResponseEntity<>(HttpStatus.OK);
        }
        return new ResponseEntity<>(HttpStatus.NOT_FOUND);
    }

}
