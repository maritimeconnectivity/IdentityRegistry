/*
 * Copyright 2017 Danish Maritime Authority
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.maritimecloud.identityregistry;

import com.deepoove.swagger.diff.SwaggerDiff;
import com.deepoove.swagger.diff.output.HtmlRender;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.test.context.junit4.SpringRunner;

import java.io.FileWriter;
import java.io.IOException;

import static org.junit.Assert.assertTrue;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class SwaggerChanges {

    @LocalServerPort
    private int port;

    @Test
    public void testSwagger() {
        String currentSwagger = "https://api.maritimecloud.net/v2/api-docs"; // TODO: needs to be changed when migrating to new url
        String newSwagger = "http://127.0.0.1:" + port + "/v2/api-docs";

        SwaggerDiff diff = SwaggerDiff.compareV2(currentSwagger, newSwagger);

        String html = new HtmlRender("Changelog", "http://deepoove.com/swagger-diff/stylesheets/demo.css")
                .render(diff);

        try {
            FileWriter fileWriter = new FileWriter("swaggerDiff.html");
            fileWriter.write(html);
            fileWriter.close();
        } catch (IOException e) {
            e.printStackTrace();
            assertTrue(false);
        }
    }
}
