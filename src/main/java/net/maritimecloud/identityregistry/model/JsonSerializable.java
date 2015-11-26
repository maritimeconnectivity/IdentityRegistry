/* Copyright (c) 2015 Danish Maritime Authority
*
* This library is free software; you can redistribute it and/or
* modify it under the terms of the GNU Lesser General Public
* License as published by the Free Software Foundation; either
* version 3 of the License, or (at your option) any later version.
*
* This library is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
* Lesser General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this library.  If not, see <http://www.gnu.org/licenses/>.
*/
package net.maritimecloud.identityregistry.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;

/**
* Should be implemented by value objects that will be serialized as JSON.
* <p/>
* To allow for a more compact JSON serialization, the VO's do not serialize null properties.
*/
@JsonIgnoreProperties(ignoreUnknown=true)
@JsonInclude(value = JsonInclude.Include.NON_NULL)
public interface JsonSerializable {
}