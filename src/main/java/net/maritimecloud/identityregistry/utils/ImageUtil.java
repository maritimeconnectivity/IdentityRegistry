/* Copyright 2016 Danish Maritime Authority.
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
package net.maritimecloud.identityregistry.utils;

import javax.imageio.ImageIO;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

/*
  Util to scale images.
  To avoid problems on headless servers set java.awt.headless=true like this:
  System.setProperty("java.awt.headless", "true");
  or this:
  -Djava.awt.headless=true
 */
public class ImageUtil {

    public static final float MAX_HEIGHT = 600.0f;
    public static final float MAX_WIDTH = 800.0f;
    public static final String OUTPUT_FORMAT = "png";

    public static ByteArrayOutputStream resize(InputStream inputStream) throws IOException {
        ByteArrayOutputStream outputImageStream = new ByteArrayOutputStream();
        BufferedImage inputImage = ImageIO.read(inputStream);
        if (inputImage == null) {
            throw new IOException("Could not read input image!");
        }
        inputStream.close();
        // If needed, find a new size for the image, so that it fits within MAX_HEIGHT and MAX_WIDTH
        int scaledHeight = inputImage.getHeight();
        int scaledWidth = inputImage.getWidth();
        if (scaledHeight > MAX_HEIGHT || scaledWidth > MAX_WIDTH) {
            float scaleByHeight = MAX_HEIGHT / scaledHeight;
            float scaleByWidth = MAX_WIDTH / scaledWidth;
            if (scaleByHeight < scaleByWidth) {
                scaledHeight = (int) Math.round(Math.floor(scaledHeight * scaleByHeight));
                scaledWidth = (int) Math.round(Math.floor(scaledWidth * scaleByHeight));
            } else {
                scaledHeight = (int) Math.round(Math.floor(scaledHeight * scaleByWidth));
                scaledWidth = (int) Math.round(Math.floor(scaledWidth * scaleByWidth));
            }
        }
        // Create output image
        BufferedImage outputImage = new BufferedImage(scaledWidth, scaledHeight, BufferedImage.TYPE_INT_ARGB);

        // Scale the input image to the output image
        Graphics2D g2d = outputImage.createGraphics();
        g2d.drawImage(inputImage, 0, 0, scaledWidth, scaledHeight, null);
        g2d.dispose();

        // write to outputstream
        ImageIO.write(outputImage, OUTPUT_FORMAT, outputImageStream);
        return outputImageStream;
    }
}
