using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace EasyFW.Core
{
    /// <summary>
    /// A simplified world for the map tab: coastlines drawn by hand at a few degrees of detail, and one point per country.
    /// It ships inside EasyFW, so the map needs no download and sends nothing anywhere.
    /// </summary>
    public enum LocationSource { Chosen, PublicIp, Windows, Guess }

    public sealed class MapLocation
    {
        public MapLocation(string country, string city, double lat, double lon, LocationSource source)
        {
            Country = country;
            City = city;
            Lat = lat;
            Lon = lon;
            Source = source;
        }

        public string Country { get; }
        public string City { get; }
        public double Lat { get; }
        public double Lon { get; }
        public LocationSource Source { get; }

        public string Text => City == null ? IpInfo.CountryName(Country) : $"{City}, {IpInfo.CountryName(Country)}";

        public string SourceText => Source == LocationSource.Chosen ? "set by you"
            : Source == LocationSource.PublicIp ? "from your public IP"
            : Source == LocationSource.Windows ? "from the Windows region"
            : "a guess";
    }

    public static class WorldGeo
    {
        /// <summary>Land outlines as longitude, latitude pairs.</summary>
        public static readonly IReadOnlyList<double[]> Land = new[]
        {
            // North and Central America
            P(-168,66, -162,70, -156,71.3, -141,69.7, -128,70, -115,68.5, -100,68, -95,71, -85,69.5, -82,66, -87,64, -94,59, -93,57, -87,55.5, -82,53, -79,55, -77,60, -78,62.5,
              -73,62, -69,59, -64,60, -61,56, -57,52, -56,50, -60,48, -65,49, -70,47, -66,44.5, -70,43.5, -70,41.7, -74,40.5, -76,38, -76,35, -78,34, -81,31.5, -80.5,28, -80,25.3,
              -81.5,25.5, -82.7,28, -84,30, -89,30.2, -94,29.5, -97.3,27.5, -97.5,22, -96,19, -94.5,18.2, -91.5,18.5, -90.5,21, -87,21.5, -88,18, -88.5,16, -84,15.8, -83.3,12,
              -83.7,10.8, -81.5,9, -79.5,9.6, -77.5,8.5, -78,7.2, -80,7.3, -81.5,7.8, -83.5,8.4, -85.7,10, -87.5,13, -91,13.9, -94,16, -97,15.8, -101,17.3, -105.5,20, -105.5,22.5,
              -109,26, -112.7,30, -114.7,31.5, -114.5,30, -112.5,27.5, -110.5,24.2, -109.9,23, -112,24.8, -114,27, -115.8,29.5, -117,32.5, -120.6,34.5, -122.5,37.5, -124,40.5,
              -124.5,43, -124,47, -123,49, -127.5,50.5, -131,54, -133.5,57.5, -137,59, -141,60, -147,60.8, -152,59, -154,57.5, -158,56.5, -163,55, -158,58.5, -162,60, -165,62,
              -164.5,64.5, -168,65.6),
            // Greenland and the Canadian Arctic
            P(-73,78, -60,82, -40,83.5, -22,82.5, -18,77, -22,72, -24,69, -32,68, -40,65, -43,60, -48,61, -52,65, -54,69, -56,73, -66,76.5),
            P(-90,73.5, -80,73.8, -70,71, -62,66.5, -65,62.8, -72,63.5, -78,64.5, -74,68, -81,69.5, -88,70.5),
            P(-125,72, -115,73.5, -105,73.5, -95,74, -90,76.5, -80,76.5, -75,79, -62,82, -80,83, -95,81.5, -110,78, -120,76, -125,74),
            P(-118,70, -105,69, -101,71, -108,73, -117,73),
            // Caribbean
            P(-85,21.9, -82,23.1, -77.5,22, -74.2,20.2, -77.5,19.8, -80,21.8, -84,21.9),
            P(-74.5,18.4, -72,19.9, -68.4,19, -68.4,18.4, -71.5,17.6, -74.4,18.1),
            P(-78.4,18.4, -76.3,18.2, -76.8,17.8, -78.2,18.1),
            P(-67.2,18.5, -65.6,18.4, -65.8,18, -67.1,18),
            // South America
            P(-77.3,8.6, -75.5,10.8, -71.5,12.4, -70,11.5, -68,10.6, -64,10.7, -61,10.3, -60,8.5, -57,6, -53,5.5, -51,4, -50,0.5, -48,-1, -44,-2.5, -40,-2.8, -35,-5.2,
              -34.8,-7.5, -35.5,-9.5, -38.5,-13, -39,-17.5, -40.5,-21.5, -44,-23, -48,-26, -48.6,-28.5, -52,-32, -54,-34.8, -57,-34.5, -58.4,-34, -57,-36.3, -57.6,-38.2,
              -62,-39, -62.3,-40.6, -65,-41, -63.8,-42, -65.3,-45, -67.5,-46.5, -66,-48, -69,-51, -68.4,-52.4, -65,-55, -69,-55.5, -71,-54, -74,-52.5, -75.5,-48, -74,-44,
              -73.5,-40, -73.5,-37, -71.6,-33, -71.5,-28, -70.5,-23, -70.2,-18.4, -72,-17, -76,-14, -79,-8, -81.2,-5.5, -80,-2.5, -80.5,-0.5, -79.5,1, -78.8,1.8, -77.5,4, -77.4,7),
            P(-61.3,-51.2, -58,-51, -57.7,-51.9, -60.6,-52.2),
            // Europe and Asia
            P(-5.6,36, -6.3,36.8, -7.5,37.2, -8.9,37, -8.8,38.7, -9.5,39.5, -8.8,42, -9.3,43, -8,43.7, -4,43.5, -1.5,43.4, -1.2,44.7, -1.2,46.2, -2.3,47.2, -4.5,47.9,
              -4.6,48.6, -1.6,48.7, -1.3,49.7, 0.2,49.5, 1.6,50.2, 2.5,51.1, 4,51.6, 4.8,53, 7,53.5, 8.6,53.9, 8.6,55.5, 8.1,57, 10.5,57.7, 10.5,56.2, 10,55, 11,54, 13.5,54.3,
              14.3,53.8, 17,54.6, 19.5,54.4, 21,55.8, 21,57, 23.5,57, 24.3,58.4, 23.5,59.2, 28,59.5, 30,60, 26,60.4, 22.5,60, 21.4,61, 21.5,63, 25,65, 25.4,65.6, 22.5,65.9,
              21.3,64.4, 19,63.4, 17.4,62, 17.1,60.6, 18.8,59.8, 16.5,57.6, 16.4,56.3, 14.3,55.5, 12.8,55.8, 11.8,57.6, 11,59, 10.4,59.2, 8,58.1, 6.6,58.1, 5,59.3, 5,61.5,
              5.3,62.4, 8.5,63.6, 10.5,64.5, 12.5,66, 14,67.5, 16,68.8, 18.5,69.8, 23,70.6, 26,71, 28.5,70.8, 31,70, 33,69.3, 36,69, 41,67.5, 39.5,66.2, 35,66.2, 34.8,64.5,
              37.8,64.3, 40.5,64.6, 44,66.2, 44.5,68.3, 46.5,68, 53.5,68.4, 58,68.8, 60.5,69.8, 66,69, 68.5,68.2, 69,69.5, 67,70.8, 68.5,72.8, 72.5,72.8, 72.2,71.2, 72.5,66.5,
              73.5,68.5, 75,72, 79,72.5, 80.5,73.5, 87,73.8, 87,75, 95,76, 100,76.5, 104,77.7, 108,76.7, 112,76, 113.5,73.5, 119,73, 126,73.5, 129,72.5, 131,70.8, 136,71.5,
              140,72.5, 146,72.3, 150,71.5, 152,70.8, 159,70.8, 160.5,69.6, 167,69.6, 170.5,70.1, 176,69.8, 180,68.9, 180,65.5, 177,64.7, 178.5,62.5, 173.5,61.7, 170,60,
              166,59.8, 163.5,59.9, 162,58, 163,56, 162,54.8, 160,53, 158.5,51.5, 156.7,51, 156,53, 155.5,56, 156.5,57.8, 158.5,58, 161.5,60.5, 163,61.7, 160,61.5, 156,61.5,
              154,59.2, 151,59, 147,59.3, 143,59.3, 141,58.5, 138,56, 135.2,54.7, 138,53.5, 141,52.6, 140.5,50, 140,48, 138.5,46.5, 135,43.5, 133,42.8, 131,42.6, 129.7,40.8,
              128,39.5, 129.4,37, 129.4,35.5, 127.5,34.7, 126.3,34.5, 126.5,36.7, 126,37.7, 124.7,38, 125.3,39.5, 124.3,40, 121.5,40.9, 119.5,39.8, 118,39.2, 117.6,38.5,
              118.8,37.4, 122.5,37.4, 120,36, 119.2,34.8, 120.8,32.6, 121.9,31, 122,29.8, 121.5,28, 119.6,25.6, 118.6,24.5, 116.5,22.9, 113.7,22.5, 110.5,21.3, 110.2,20.3,
              109.7,21.5, 108,21.6, 106.7,20.7, 105.7,19, 106.5,17.5, 108.7,15.4, 109.3,13, 109,11.5, 107,10.4, 105,8.6, 104.8,10.2, 103.5,10.6, 102.6,12.2, 101,12.6, 100,13.4,
              99.2,10.3, 100.4,7.5, 101.2,6.9, 102.1,6.2, 103.4,4.8, 103.5,2.6, 104.2,1.4, 103.5,1.3, 101.4,2.8, 100.4,4.2, 100.2,5.5, 98.3,7.8, 98.7,10.5, 98.5,13.1, 97.6,16.5,
              95.4,15.8, 94.3,16, 94.6,18.2, 93.5,19.5, 92.3,21.5, 91.8,22.4, 90.5,22, 89,21.9, 87,21.5, 86.9,20.5, 85,19.5, 82.3,16.6, 80.3,15.9, 80.2,13.3, 79.9,10.3,
              78.3,8.9, 77.5,8.1, 76.6,8.9, 75.8,11.3, 74.8,12.9, 73.5,15.8, 72.8,19.2, 72.6,21.4, 70.5,20.9, 69,22.4, 70.3,22.9, 68.4,23.6, 67.4,23.9, 66.4,25.4, 64.5,25.2,
              61.5,25.1, 58.5,25.6, 57.4,25.7, 56.4,27.1, 54.7,26.5, 51.5,27.9, 50.2,30.1, 48,30.4, 48.5,29.5, 48.3,28, 49.9,26.3, 50.2,25.6, 50.8,24.7, 51.6,24.2, 52.6,24.2,
              54.6,24.3, 56,26, 56.4,24.9, 57.4,23.9, 58.7,23.6, 59.8,22.4, 58.5,20.4, 57.7,18.9, 56.3,17.9, 55.3,17.2, 52.2,15.9, 49.6,14.7, 48.7,14, 45.6,13.3, 43.5,12.6,
              42.6,15.2, 42.7,16.5, 41.2,19, 39.1,21.3, 39,22.6, 37.5,24.3, 35.2,28, 34.9,29.5, 34.2,31.3, 34.9,32.8, 35.5,34.3, 36,35.8, 35.8,36.7, 34.5,36.8, 32.5,36.1,
              30,36.2, 28,36.7, 27.2,37.9, 26.3,38.3, 26.2,39.5, 26.6,40.4, 26.2,40.6, 24,40.9, 22.6,40.3, 23.3,39.2, 23.2,38, 22.9,36.5, 21.7,36.9, 21.1,38.3, 20.2,39.5,
              19.4,40.3, 19.4,41.8, 16.5,43.4, 15.2,44.3, 13.6,45.3, 12.3,45.3, 12.4,44.2, 13.6,43.5, 16,41.4, 18.5,40.2, 17.2,39.4, 16.6,38.4, 15.7,38, 16.2,39.2, 15.5,40.1,
              14,40.8, 12.6,41.5, 11.1,42.4, 10.2,43.9, 8.7,44.4, 7.5,43.8, 6.2,43.1, 4.6,43.4, 3.1,43.1, 3.2,41.9, 0.8,41, 0,39.8, -0.3,38.4, -2,36.8, -4.4,36.7),
            // Africa
            P(-5.9,35.8, -2,35.1, 1,36.5, 3.5,36.8, 8.6,36.9, 10.2,37.2, 11,36.8, 10.5,36, 11.1,35.2, 10.2,34.3, 10.2,33.6, 11.5,33.1, 15.2,32.3, 15.7,31.5, 18.6,30.4, 20,30.9,
              20.1,32.2, 21.6,32.9, 25,32, 29,30.9, 31,31.6, 32.3,31.2, 34.2,31.3, 34.9,29.5, 34.2,27.8, 32.6,29.9, 32.9,28, 33.9,26.6, 35.5,24, 37.2,21, 37.4,18.8, 38.6,17.9,
              39.5,15.5, 41.2,14.5, 43.3,12.5, 44.3,10.4, 46,10.7, 51.2,11.8, 51,10.4, 50.8,9.3, 49,6, 47.9,4.5, 46,2.2, 43.5,-0.5, 41.7,-1.9, 40.2,-2.8, 39.2,-4.7, 38.8,-6.5,
              39.4,-8, 39.8,-10.2, 40.5,-12.6, 40.6,-15.5, 37.4,-17.5, 35.3,-22.1, 35.5,-24, 32.9,-26, 32.6,-28.6, 31,-29.9, 28,-33, 25.7,-34, 22.5,-34, 20,-34.8, 18.4,-34.1,
              18.2,-32.4, 17.1,-29.5, 15.2,-27, 14.5,-22.9, 13.4,-20.9, 11.8,-17.4, 11.9,-15.7, 12.6,-13.2, 13.7,-10.7, 13.2,-8.6, 12.2,-6, 12.3,-4.6, 11,-3.9, 9.2,-1, 9.4,1.3,
              9.8,3.1, 8.5,4.5, 5.9,4.3, 4.4,6.3, 1.9,6.2, -2,4.7, -4,5.2, -7.5,4.4, -9.3,5.5, -11.4,6.9, -13.2,8.9, -15,10.9, -16.7,12.4, -17.5,14.7, -16.5,16.2, -16.1,18.5,
              -17,21, -16,23.7, -14.4,26.2, -13,27.7, -11.5,28.2, -9.8,29.9, -9.8,31.4, -6.9,34),
            P(49.4,-12, 50.5,-15.5, 49.4,-17.8, 47.1,-24.9, 45.2,-25.6, 43.6,-23.5, 44.2,-20.2, 44,-17.4, 46.3,-15.8, 48,-13.6),
            // Islands of Europe
            P(-5.7,50, -3,50.6, 1.4,51.2, 1.7,52.7, 0.2,53.5, -0.3,54.5, -1.6,55.6, -2,57, -1.8,57.6, -3.3,58.6, -5,58.6, -6.2,57.5, -5.6,56.3, -4.8,55.6, -5.1,54.8, -3.2,54.9,
              -3,53.4, -4.6,53.3, -4.2,52.3, -5.3,51.8, -3,51.4, -4.5,51.2),
            P(-6,52.2, -6.2,53.9, -5.6,54.6, -7.3,55.4, -8.5,54.4, -10.1,54.2, -9.9,53.4, -9.4,52.6, -10.4,51.8, -9.6,51.5, -8,51.8),
            P(-22,63.9, -24.3,65.6, -22.5,66.4, -16,66.5, -13.6,65.1, -15,64.3, -18.7,63.4),
            P(12.4,38, 15.6,38.3, 15.1,36.7),
            P(8.4,41, 9.6,41, 9.6,39.1, 8.4,39),
            P(8.6,43, 9.5,43, 9.3,41.4, 8.7,41.6),
            P(23.5,35.3, 26.3,35.2, 24.8,34.9),
            P(32.3,34.7, 34,35.1, 34.6,35.7, 32.9,35.2),
            P(11,78.5, 16,79.9, 22,80.3, 27,80, 22,78, 17,76.6, 14,77.5),
            P(52,71.5, 56,74.5, 62,76.3, 69,76.9, 66,75.7, 58,73, 56,70.6),
            // Islands of Asia
            P(79.8,8, 80.2,9.8, 81.9,7.5, 81.2,6.2, 80.1,6),
            P(130,31.3, 129.7,33.5, 131,34.4, 132.5,35.4, 135.5,35.7, 136.8,37.3, 138.5,37.8, 140,40, 139.9,41.2, 141.5,41.4, 141.9,39.5, 141,38.3, 140.9,36.9, 140.7,35.2,
              139.8,34.9, 138.8,34.6, 137,34.6, 135.8,33.5, 135,34.5, 133,33.3, 132,33, 131.4,31.4),
            P(140,41.5, 140.4,43.3, 141.6,45.4, 143.2,44.2, 145.3,43.3, 144,42.9, 143.2,42, 141,41.8),
            P(142,46, 143.5,46.5, 143,49.5, 144.6,49, 142.8,54.3, 142.2,54.2, 141.8,51, 142.1,47.5),
            P(120.1,23, 121,25.1, 122,25, 121.5,23.3, 120.8,21.9),
            P(108.7,19.2, 110.5,20.1, 111,19.6, 109.6,18.2),
            P(120,18.5, 122.2,18.5, 122.5,17, 121.5,15.5, 124,13, 123,13.5, 120.5,14.5, 119.8,16.4),
            P(122,7, 125.5,9.8, 126.5,7, 125.3,5.8, 124,6.8),
            P(122,11.8, 125,11.5, 125.5,10, 123,9.2),
            P(109,1.5, 109.6,2, 111.5,2.7, 113,3.2, 115.4,5.3, 116.8,7, 119.2,5.4, 118.2,4.4, 117.7,1.4, 119,0.9, 117.5,0.5, 116.6,-1.5, 116.3,-3.9, 114.6,-4, 111.7,-3,
              110.2,-2.9, 109.6,-0.8),
            P(95.3,5.6, 97.5,5.2, 100.3,2.1, 103.8,-1, 106,-3.2, 105.8,-5.8, 104.6,-5.9, 102.3,-4, 100.7,-2.3, 98.6,1.6, 96.4,3.7),
            P(105.2,-6.8, 106.1,-5.9, 110.3,-6.9, 112.6,-6.9, 114.4,-7.8, 114.6,-8.7, 110.5,-8.2, 106.5,-7.4),
            P(119.4,-5.5, 118.8,-2.8, 119.7,0, 120.9,1.3, 124.8,1.5, 123,0.5, 121.5,-0.8, 123.3,-1, 121.3,-1.9, 122.7,-4.6, 121.6,-4.8, 120.4,-5.6),
            P(115.5,-8.2, 119,-8.3, 122.5,-8.2, 125.5,-8.2, 127,-8.4, 124.5,-9.5, 120,-9.4, 117,-9),
            // Oceania
            P(131,-1.4, 134,-0.9, 135.5,-3.4, 138,-1.6, 141,-2.6, 145.8,-5.4, 147.6,-6.1, 147.2,-7.8, 150,-10.3, 147.4,-10, 145.4,-7.9, 143.3,-9.2, 141,-9.1, 139,-8.1,
              138.9,-6.8, 137.9,-5.3, 135.2,-4.4, 132.7,-4.1, 131.9,-2.8),
            P(113.5,-22, 114.2,-26.3, 115,-29.5, 115.7,-33.6, 115,-34.3, 117.9,-35.1, 120,-33.9, 123.6,-33.9, 126.1,-32.2, 129,-31.6, 131.3,-31.5, 134.2,-32.6, 135.6,-34.9,
              137.7,-33, 137.8,-35.6, 139.6,-37.9, 141.6,-38.4, 143.6,-38.8, 146.3,-39.1, 148.3,-37.8, 150,-37.4, 151.3,-33.8, 153.1,-30.4, 153.6,-28.5, 153,-25.3, 150.9,-22.6,
              149.2,-21, 146.4,-18.9, 145.4,-14.9, 143.6,-14.2, 142.5,-10.7, 141.6,-12.9, 141.6,-16.5, 140.3,-17.7, 138.4,-16.8, 136.5,-15.8, 135.5,-14.7, 136.8,-12.2,
              132.6,-11.5, 130.6,-12.3, 129.4,-14.9, 127.8,-14.3, 125.1,-14.5, 123.3,-16.8, 122.2,-18.2, 121,-19.6, 117,-20.6, 114.6,-21.8),
            P(144.7,-40.7, 148.3,-40.9, 148,-43.2, 146,-43.6, 145.2,-42.2),
            P(172.7,-34.4, 174.6,-36.2, 176,-37.6, 178.5,-37.7, 177.9,-39.2, 176.9,-39.4, 175.3,-41.6, 174.6,-41.3, 175,-39.9, 173.8,-39.2, 174.6,-37.3),
            P(172.7,-40.5, 174.3,-41.7, 173.2,-43, 171.2,-44.4, 170.6,-45.9, 169,-46.6, 166.5,-46, 167.8,-44.3, 170.6,-43, 172.1,-41.3),
            P(177.2,-17.4, 178.6,-17.6, 178.4,-18.3, 177.3,-18.1),
            P(164,-20.2, 165.5,-21, 167,-22.3, 166.4,-22.3, 164.2,-20.6),
        };

        /// <summary>Seas inside the outlines above.</summary>
        public static readonly IReadOnlyList<double[]> Water = new[]
        {
            P(28,41.2, 29.5,41.2, 31.5,41.2, 33.5,42, 36,41.6, 38.5,40.9, 41.5,41.5, 41.7,42.6, 39.5,44, 37.5,44.7, 39.2,47.2, 35,46.3, 36.5,45.3, 33.5,44.5, 32.5,45.4, 33.6,46,
              31.5,46.6, 30.2,45.8, 29.6,45.2, 28.6,44, 27.9,42.6),
            P(46.8,44.6, 47.5,45.7, 49.2,46.5, 51.2,47, 53,46.8, 53.2,45.3, 51.3,44.5, 52.7,42, 54,40.8, 53.9,38, 53.9,36.9, 51.5,36.8, 49,37.6, 48.9,38.4, 49.4,40.2, 50.3,40.4,
              49.5,41, 48.6,41.8, 47.5,43),
        };

        private static double[] P(params double[] lonLat) => lonLat;

        /// <summary>Latitude, longitude of a point well inside each country, near where most of its people live.</summary>
        private const string Points =
            "AD 42.5 1.5|AE 24.2 54.4|AF 33.9 67.7|AG 17.1 -61.8|AI 18.2 -63.1|AL 41.2 20.2|AM 40.1 45|AO -11.2 17.9|AR -34.6 -62|AS -14.3 -170.7|AT 47.5 14.6|AU -28 140|" +
            "AW 12.5 -70|AX 60.2 20|AZ 40.4 48.5|BA 43.9 17.7|BB 13.2 -59.5|BD 23.7 90.4|BE 50.6 4.5|BF 12.2 -1.6|BG 42.7 25.5|BH 26 50.6|BI -3.4 29.9|BJ 9.3 2.3|" +
            "BL 17.9 -62.8|BM 32.3 -64.8|BN 4.5 114.7|BO -16.3 -63.6|BQ 12.2 -68.3|BR -15 -48|BS 25 -77.4|BT 27.5 90.4|BW -22.3 24.7|BY 53.7 28|BZ 17.2 -88.5|CA 50 -95|" +
            "CD -4 21.8|CF 6.6 20.9|CG -0.7 15.5|CH 46.8 8.2|CI 7.5 -5.5|CK -21.2 -159.8|CL -33.5 -70.8|CM 5.5 12.4|CN 33 110|CO 4.6 -74.3|CR 9.9 -84|CU 21.8 -78.5|" +
            "CV 15.5 -23.8|CW 12.2 -69|CY 35 33.2|CZ 49.8 15.5|DE 51 10.4|DJ 11.6 42.8|DK 55.9 9.6|DM 15.4 -61.4|DO 18.7 -70.2|DZ 32 3|EC -1.8 -78.2|EE 58.7 25.5|" +
            "EG 28 30.8|EH 24.2 -12.9|ER 15.2 39|ES 40.3 -3.7|ET 9.1 39.5|EU 50.1 8.7|FI 62 25.5|FJ -17.8 178|FK -51.7 -59|FM 7.4 150.6|FO 62 -6.9|FR 46.6 2.4|" +
            "GA -0.8 11.6|GB 53 -1.8|GD 12.1 -61.7|GE 42 43.6|GF 4 -53.1|GG 49.5 -2.6|GH 7.2 -1.2|GI 36.1 -5.4|GL 72 -40|GM 13.4 -15.5|GN 10.4 -10.9|GP 16.2 -61.6|" +
            "GQ 1.6 10.3|GR 39.3 22|GT 15.5 -90.4|GU 13.4 144.8|GW 12 -15|GY 5.5 -58.8|HK 22.3 114.2|HN 14.8 -86.6|HR 45.3 16.2|HT 18.9 -72.4|HU 47.2 19.5|ID -4 115|" +
            "IE 53.2 -8|IL 31.5 34.9|IM 54.2 -4.5|IN 22 79|IO -6.3 71.9|IQ 33 44|IR 33 53|IS 64.6 -19|IT 42.5 12.6|JE 49.2 -2.1|JM 18.1 -77.3|JO 31.3 36.3|JP 36 138.5|" +
            "KE 0 37.9|KG 41.4 74.8|KH 12.4 104.9|KI 1.9 -157.4|KM -11.9 43.9|KN 17.3 -62.7|KP 39.8 126.8|KR 36.4 127.8|KW 29.3 47.7|KY 19.3 -81.3|KZ 48.5 67|" +
            "LA 18.8 103.5|LB 33.9 35.8|LC 13.9 -61|LI 47.2 9.6|LK 7.6 80.7|LR 6.6 -9.4|LS -29.5 28.2|LT 55.3 23.9|LU 49.7 6.1|LV 56.9 24.8|LY 29 17|MA 32 -6.5|" +
            "MC 43.7 7.4|MD 47.2 28.5|ME 42.7 19.3|MF 18.1 -63.1|MG -19 46.8|MH 7.1 171.2|MK 41.6 21.7|ML 14.5 -4|MM 20 96|MN 47 104|MO 22.2 113.5|MP 15.2 145.7|" +
            "MQ 14.6 -61|MR 19 -11|MS 16.7 -62.2|MT 35.9 14.4|MU -20.3 57.6|MV 3.2 73.2|MW -13.3 34|MX 21 -101|MY 3.6 101.8|MZ -18 35|NA -22 17.5|NC -21.3 165.6|" +
            "NE 15 8|NF -29 168|NG 9 8|NI 12.8 -85.4|NL 52.2 5.4|NO 60.5 9|NP 28 84.3|NR -0.5 166.9|NU -19.1 -169.9|NZ -39 175.5|OM 22 57.5|PA 8.6 -80.4|PE -10 -75.5|" +
            "PF -17.6 -149.5|PG -6.3 145|PH 13 121.8|PK 30 70.5|PL 52 19.3|PM 46.9 -56.3|PR 18.2 -66.5|PS 31.9 35.2|PT 39.6 -8.3|PW 7.5 134.6|PY -24 -57.5|QA 25.3 51.2|" +
            "RE -21.1 55.5|RO 45.8 24.9|RS 44 20.9|RU 56 44|RW -1.9 29.9|SA 24 45|SB -9.6 160.2|SC -4.7 55.5|SD 15 31|SE 60 16|SG 1.35 103.8|SH -15.9 -5.7|SI 46.1 14.8|" +
            "SK 48.7 19.5|SL 8.5 -11.8|SM 43.9 12.5|SN 14.6 -14.8|SO 5 46|SR 4.5 -55.9|SS 7.5 30.5|ST 0.3 6.6|SV 13.7 -88.9|SX 18 -63.1|SY 34.8 37.5|SZ -26.5 31.5|" +
            "TC 21.7 -71.8|TD 13 18.5|TG 8 1.1|TH 15 101|TJ 38.7 70.5|TL -8.8 125.8|TM 39 59|TN 35 9.5|TO -21.2 -175.2|TR 39.3 33|TT 10.5 -61.3|TV -7.1 177.6|" +
            "TW 23.8 121|TZ -6.3 35|UA 49 31.5|UG 1.4 32.4|US 39 -97|UY -33 -56|UZ 41 64.5|VA 41.9 12.45|VC 13.3 -61.2|VE 8 -66|VG 18.4 -64.6|VI 18.3 -64.9|" +
            "VN 16 107.5|VU -15.4 166.9|WF -13.8 -177.2|WS -13.8 -172.1|XK 42.6 20.9|YE 15.4 47.5|YT -12.8 45.2|ZA -28.5 25|ZM -14 27.8|ZW -19 29.8";

        private static readonly Dictionary<string, (double Lat, double Lon)> CountryPoints = Points.Split('|')
            .Select(e => e.Split(' '))
            .ToDictionary(p => p[0], p => (double.Parse(p[1], CultureInfo.InvariantCulture), double.Parse(p[2], CultureInfo.InvariantCulture)), StringComparer.OrdinalIgnoreCase);

        public static IEnumerable<string> Countries => CountryPoints.Keys;

        /// <summary>Country code, city, latitude, longitude: capitals and large cities, for choosing where this PC is.</summary>
        private const string CityList =
            "AE Abu Dhabi 24.45 54.38|AE Dubai 25.2 55.27|AE Sharjah 25.35 55.4|AF Kabul 34.53 69.17|AL Tirana 41.33 19.82|AM Yerevan 40.18 44.51|AO Luanda -8.84 13.23|" +
            "AR Buenos Aires -34.6 -58.38|AR Córdoba -31.42 -64.18|AR Rosario -32.95 -60.65|AT Vienna 48.21 16.37|AT Graz 47.07 15.44|AU Sydney -33.87 151.21|" +
            "AU Melbourne -37.81 144.96|AU Brisbane -27.47 153.03|AU Perth -31.95 115.86|AU Adelaide -34.93 138.6|AU Canberra -35.28 149.13|AZ Baku 40.41 49.87|" +
            "BA Sarajevo 43.86 18.41|BD Dhaka 23.81 90.41|BD Chittagong 22.36 91.78|BE Brussels 50.85 4.35|BE Antwerp 51.22 4.4|BG Sofia 42.7 23.32|BH Manama 26.23 50.59|" +
            "BO La Paz -16.5 -68.15|BR São Paulo -23.55 -46.63|BR Rio de Janeiro -22.91 -43.17|BR Brasília -15.79 -47.88|BR Salvador -12.97 -38.5|BR Fortaleza -3.73 -38.53|" +
            "BR Belo Horizonte -19.92 -43.94|BR Porto Alegre -30.03 -51.23|BR Manaus -3.12 -60.02|BY Minsk 53.9 27.56|CA Toronto 43.65 -79.38|CA Montreal 45.5 -73.57|" +
            "CA Vancouver 49.28 -123.12|CA Calgary 51.05 -114.07|CA Ottawa 45.42 -75.7|CA Edmonton 53.55 -113.49|CD Kinshasa -4.44 15.27|CH Zurich 47.38 8.54|CH Geneva 46.2 6.14|" +
            "CH Bern 46.95 7.45|CI Abidjan 5.36 -4.01|CL Santiago -33.45 -70.67|CM Douala 4.05 9.77|CM Yaoundé 3.85 11.5|CN Beijing 39.9 116.41|CN Shanghai 31.23 121.47|" +
            "CN Guangzhou 23.13 113.26|CN Shenzhen 22.54 114.06|CN Chengdu 30.57 104.07|CN Wuhan 30.59 114.31|CN Hangzhou 30.27 120.16|CN Chongqing 29.56 106.55|" +
            "CN Xi'an 34.34 108.94|CO Bogotá 4.71 -74.07|CO Medellín 6.24 -75.58|CO Cali 3.45 -76.53|CR San José 9.93 -84.08|CU Havana 23.11 -82.37|CY Nicosia 35.19 33.38|" +
            "CZ Prague 50.08 14.44|CZ Brno 49.2 16.61|DE Berlin 52.52 13.4|DE Hamburg 53.55 9.99|DE Munich 48.14 11.58|DE Cologne 50.94 6.96|DE Frankfurt 50.11 8.68|" +
            "DE Stuttgart 48.78 9.18|DE Düsseldorf 51.23 6.78|DK Copenhagen 55.68 12.57|DK Aarhus 56.16 10.2|DO Santo Domingo 18.49 -69.93|DZ Algiers 36.75 3.06|" +
            "DZ Oran 35.7 -0.63|EC Quito -0.18 -78.47|EC Guayaquil -2.17 -79.92|EE Tallinn 59.44 24.75|EG Cairo 30.04 31.24|EG Alexandria 31.2 29.92|EG Giza 30.01 31.21|" +
            "EG Port Said 31.27 32.3|EG Suez 29.97 32.53|EG Mansoura 31.04 31.38|EG Tanta 30.79 31|EG Asyut 27.18 31.18|EG Luxor 25.69 32.64|EG Aswan 24.09 32.9|" +
            "EG Hurghada 27.26 33.81|EG Sharm El Sheikh 27.92 34.33|EG Ismailia 30.6 32.27|EG Zagazig 30.59 31.5|EG Damietta 31.42 31.81|EG Minya 28.11 30.74|" +
            "ES Madrid 40.42 -3.7|ES Barcelona 41.39 2.17|ES Valencia 39.47 -0.38|ES Seville 37.39 -5.98|ES Bilbao 43.26 -2.93|ES Málaga 36.72 -4.42|ET Addis Ababa 9.03 38.74|" +
            "FI Helsinki 60.17 24.94|FI Tampere 61.5 23.79|FR Paris 48.86 2.35|FR Marseille 43.3 5.37|FR Lyon 45.76 4.84|FR Toulouse 43.6 1.44|FR Nice 43.7 7.27|FR Lille 50.63 3.06|" +
            "FR Bordeaux 44.84 -0.58|FR Strasbourg 48.57 7.75|GB London 51.51 -0.13|GB Manchester 53.48 -2.24|GB Birmingham 52.49 -1.89|GB Glasgow 55.86 -4.25|" +
            "GB Edinburgh 55.95 -3.19|GB Leeds 53.8 -1.55|GB Liverpool 53.41 -2.98|GB Bristol 51.45 -2.59|GB Belfast 54.6 -5.93|GB Cardiff 51.48 -3.18|GE Tbilisi 41.72 44.79|" +
            "GH Accra 5.6 -0.19|GR Athens 37.98 23.73|GR Thessaloniki 40.64 22.94|GT Guatemala City 14.63 -90.51|HK Hong Kong 22.32 114.17|HN Tegucigalpa 14.07 -87.19|" +
            "HR Zagreb 45.81 15.98|HU Budapest 47.5 19.04|ID Jakarta -6.21 106.85|ID Surabaya -7.25 112.75|ID Bandung -6.92 107.62|ID Medan 3.59 98.67|ID Denpasar -8.65 115.22|" +
            "IE Dublin 53.35 -6.26|IE Cork 51.9 -8.47|IL Tel Aviv 32.09 34.78|IL Jerusalem 31.77 35.21|IL Haifa 32.79 34.99|IN Mumbai 19.08 72.88|IN Delhi 28.61 77.21|" +
            "IN Bengaluru 12.97 77.59|IN Hyderabad 17.39 78.49|IN Chennai 13.08 80.27|IN Kolkata 22.57 88.36|IN Pune 18.52 73.86|IN Ahmedabad 23.02 72.57|IN Jaipur 26.91 75.79|" +
            "IQ Baghdad 33.31 44.36|IQ Basra 30.51 47.78|IQ Erbil 36.19 44.01|IR Tehran 35.69 51.39|IR Mashhad 36.3 59.6|IR Isfahan 32.65 51.67|IR Shiraz 29.59 52.58|" +
            "IS Reykjavík 64.15 -21.94|IT Rome 41.9 12.5|IT Milan 45.46 9.19|IT Naples 40.85 14.27|IT Turin 45.07 7.69|IT Florence 43.77 11.26|IT Bologna 44.49 11.34|" +
            "IT Palermo 38.12 13.36|JM Kingston 18.02 -76.8|JO Amman 31.95 35.93|JO Irbid 32.56 35.85|JO Aqaba 29.53 35.01|JP Tokyo 35.68 139.69|JP Osaka 34.69 135.5|" +
            "JP Nagoya 35.18 136.91|JP Yokohama 35.44 139.64|JP Sapporo 43.06 141.35|JP Fukuoka 33.59 130.4|JP Kyoto 35.01 135.77|KE Nairobi -1.29 36.82|KE Mombasa -4.04 39.67|" +
            "KH Phnom Penh 11.56 104.92|KR Seoul 37.57 126.98|KR Busan 35.18 129.08|KR Incheon 37.46 126.71|KW Kuwait City 29.38 47.99|KZ Almaty 43.24 76.89|KZ Astana 51.17 71.45|" +
            "LB Beirut 33.89 35.5|LK Colombo 6.93 79.86|LT Vilnius 54.69 25.28|LU Luxembourg 49.61 6.13|LV Riga 56.95 24.11|LY Tripoli 32.89 13.19|LY Benghazi 32.12 20.07|" +
            "MA Casablanca 33.57 -7.59|MA Rabat 34.02 -6.83|MA Marrakesh 31.63 -7.98|MA Fez 34.03 -5|MA Tangier 35.76 -5.83|MD Chișinău 47.01 28.86|MK Skopje 42 21.43|" +
            "MM Yangon 16.87 96.2|MN Ulaanbaatar 47.89 106.91|MT Valletta 35.9 14.51|MX Mexico City 19.43 -99.13|MX Guadalajara 20.66 -103.35|MX Monterrey 25.69 -100.32|" +
            "MX Tijuana 32.51 -117.04|MX Cancún 21.16 -86.85|MY Kuala Lumpur 3.14 101.69|MY Penang 5.41 100.33|MY Johor Bahru 1.49 103.74|NG Lagos 6.52 3.38|NG Abuja 9.08 7.4|" +
            "NG Kano 12 8.52|NL Amsterdam 52.37 4.9|NL Rotterdam 51.92 4.48|NL The Hague 52.08 4.3|NL Utrecht 52.09 5.12|NL Eindhoven 51.44 5.47|NO Oslo 59.91 10.75|" +
            "NO Bergen 60.39 5.32|NP Kathmandu 27.72 85.32|NZ Auckland -36.85 174.76|NZ Wellington -41.29 174.78|NZ Christchurch -43.53 172.64|OM Muscat 23.59 58.41|" +
            "OM Salalah 17.02 54.09|PA Panama City 8.98 -79.52|PE Lima -12.05 -77.04|PH Manila 14.6 120.98|PH Cebu 10.32 123.89|PH Davao 7.19 125.46|PK Karachi 24.86 67.01|" +
            "PK Lahore 31.55 74.34|PK Islamabad 33.68 73.05|PL Warsaw 52.23 21.01|PL Kraków 50.06 19.94|PL Wrocław 51.11 17.04|PL Gdańsk 54.35 18.65|PS Ramallah 31.9 35.2|" +
            "PS Gaza 31.5 34.47|PT Lisbon 38.72 -9.14|PT Porto 41.15 -8.61|PY Asunción -25.26 -57.58|QA Doha 25.29 51.53|RO Bucharest 44.43 26.1|RO Cluj-Napoca 46.77 23.6|" +
            "RS Belgrade 44.79 20.45|RU Moscow 55.76 37.62|RU Saint Petersburg 59.93 30.34|RU Novosibirsk 55.03 82.92|RU Yekaterinburg 56.84 60.61|RU Kazan 55.8 49.11|" +
            "RU Vladivostok 43.12 131.89|SA Riyadh 24.71 46.68|SA Jeddah 21.49 39.19|SA Mecca 21.39 39.86|SA Medina 24.47 39.61|SA Dammam 26.43 50.1|SA Khobar 26.22 50.2|" +
            "SA Tabuk 28.38 36.57|SA Abha 18.22 42.5|SD Khartoum 15.5 32.56|SE Stockholm 59.33 18.07|SE Gothenburg 57.71 11.97|SE Malmö 55.6 13|SG Singapore 1.35 103.82|" +
            "SI Ljubljana 46.06 14.51|SK Bratislava 48.15 17.11|SN Dakar 14.72 -17.47|SO Mogadishu 2.05 45.32|SY Damascus 33.51 36.29|SY Aleppo 36.2 37.13|TH Bangkok 13.76 100.5|" +
            "TH Chiang Mai 18.79 98.98|TH Phuket 7.88 98.39|TN Tunis 36.81 10.18|TN Sfax 34.74 10.76|TR Istanbul 41.01 28.98|TR Ankara 39.93 32.86|TR Izmir 38.42 27.14|" +
            "TR Antalya 36.9 30.7|TR Bursa 40.19 29.06|TW Taipei 25.03 121.57|TW Kaohsiung 22.63 120.3|TZ Dar es Salaam -6.79 39.21|UA Kyiv 50.45 30.52|UA Kharkiv 49.99 36.23|" +
            "UA Odesa 46.48 30.72|UA Lviv 49.84 24.03|UG Kampala 0.35 32.58|US New York 40.71 -74.01|US Los Angeles 34.05 -118.24|US Chicago 41.88 -87.63|US Houston 29.76 -95.37|" +
            "US Phoenix 33.45 -112.07|US Philadelphia 39.95 -75.17|US San Antonio 29.42 -98.49|US San Diego 32.72 -117.16|US Dallas 32.78 -96.8|US San Jose 37.34 -121.89|" +
            "US San Francisco 37.77 -122.42|US Seattle 47.61 -122.33|US Denver 39.74 -104.99|US Washington 38.91 -77.04|US Boston 42.36 -71.06|US Atlanta 33.75 -84.39|" +
            "US Miami 25.76 -80.19|US Las Vegas 36.17 -115.14|US Detroit 42.33 -83.05|US Minneapolis 44.98 -93.27|US Portland 45.52 -122.68|US Austin 30.27 -97.74|" +
            "US Ashburn 39.04 -77.49|UY Montevideo -34.9 -56.16|UZ Tashkent 41.3 69.24|VE Caracas 10.48 -66.9|VN Hanoi 21.03 105.85|VN Ho Chi Minh City 10.82 106.63|" +
            "VN Da Nang 16.05 108.2|YE Sana'a 15.37 44.19|YE Aden 12.79 45.04|ZA Johannesburg -26.2 28.05|ZA Cape Town -33.92 18.42|ZA Durban -29.86 31.02|ZA Pretoria -25.75 28.19|" +
            "ZM Lusaka -15.39 28.32|ZW Harare -17.83 31.05";

        public sealed class City
        {
            public string Country, Name;
            public double Lat, Lon;
        }

        private static readonly List<City> CityPoints = CityList.Split('|').Select(e =>
        {
            var parts = e.Split(' ');
            var n = parts.Length;
            return new City
            {
                Country = parts[0], Name = string.Join(" ", parts.Skip(1).Take(n - 3)),
                Lat = double.Parse(parts[n - 2], CultureInfo.InvariantCulture), Lon = double.Parse(parts[n - 1], CultureInfo.InvariantCulture)
            };
        }).ToList();

        /// <summary>Known cities of a country, by name.</summary>
        public static List<City> CitiesOf(string country) =>
            CityPoints.Where(c => string.Equals(c.Country, country, StringComparison.OrdinalIgnoreCase)).OrderBy(c => c.Name, StringComparer.CurrentCultureIgnoreCase).ToList();

        public static City FindCity(string country, string name) =>
            string.IsNullOrEmpty(name) ? null : CityPoints.FirstOrDefault(c => string.Equals(c.Country, country, StringComparison.OrdinalIgnoreCase) && string.Equals(c.Name, name, StringComparison.OrdinalIgnoreCase));

        /// <summary>False for "LAN", unknown codes and null.</summary>
        public static bool TryLocate(string countryCode, out double lat, out double lon)
        {
            lat = lon = 0;
            if (string.IsNullOrEmpty(countryCode) || !CountryPoints.TryGetValue(countryCode, out var p)) return false;
            lat = p.Lat;
            lon = p.Lon;
            return true;
        }

        /// <summary>The country whose point is closest, for "set my location here".</summary>
        public static string Nearest(double lat, double lon) =>
            CountryPoints.OrderBy(c => Math.Pow(c.Value.Lat - lat, 2) + Math.Pow((c.Value.Lon - lon) * Math.Cos(lat * Math.PI / 180), 2)).First().Key;

        /// <summary>The map leaves out the far north and Antarctica, where nothing connects from.</summary>
        public const double North = 84, South = -58;
        private const double Step = 0.5;
        private static readonly Lazy<bool[,]> Mask = new Lazy<bool[,]>(BuildMask);

        /// <summary>Whether a point is on land, used to lay the dots of the map. Exact, and slow.</summary>
        public static bool IsLand(double lon, double lat) => Land.Any(p => Inside(p, lon, lat)) && !Water.Any(p => Inside(p, lon, lat));

        /// <summary>Whether a point is on land, read from a half-degree grid worked out once.</summary>
        public static bool IsLandFast(double lon, double lat)
        {
            var row = (int)Math.Floor((North - lat) / Step);
            var col = (int)Math.Floor((lon + 180) / Step);
            var m = Mask.Value;
            return row >= 0 && col >= 0 && row < m.GetLength(0) && col < m.GetLength(1) && m[row, col];
        }

        private static bool[,] BuildMask()
        {
            var m = new bool[(int)((North - South) / Step), (int)(360 / Step)];
            Fill(m, Land, true);
            Fill(m, Water, false);
            return m;
        }

        /// <summary>Scanline fill: for each row, the outline's crossings pair up into runs of inside cells.</summary>
        private static void Fill(bool[,] m, IEnumerable<double[]> polys, bool value)
        {
            var xs = new List<double>();
            foreach (var poly in polys)
            {
                var n = poly.Length / 2;
                for (var r = 0; r < m.GetLength(0); r++)
                {
                    var lat = North - (r + 0.5) * Step;
                    xs.Clear();
                    for (int i = 0, j = n - 1; i < n; j = i++)
                    {
                        double xi = poly[i * 2], yi = poly[i * 2 + 1], xj = poly[j * 2], yj = poly[j * 2 + 1];
                        if ((yi > lat) != (yj > lat)) xs.Add((xj - xi) * (lat - yi) / (yj - yi) + xi);
                    }
                    xs.Sort();
                    for (var k = 0; k + 1 < xs.Count; k += 2)
                    {
                        var c0 = Math.Max(0, (int)Math.Ceiling((xs[k] + 180) / Step - 0.5));
                        var c1 = Math.Min(m.GetLength(1) - 1, (int)Math.Floor((xs[k + 1] + 180) / Step - 0.5));
                        for (var c = c0; c <= c1; c++) m[r, c] = value;
                    }
                }
            }
        }

        private static bool Inside(double[] poly, double x, double y)
        {
            var inside = false;
            var n = poly.Length / 2;
            for (int i = 0, j = n - 1; i < n; j = i++)
            {
                double xi = poly[i * 2], yi = poly[i * 2 + 1], xj = poly[j * 2], yj = poly[j * 2 + 1];
                if ((yi > y) != (yj > y) && x < (xj - xi) * (y - yi) / (yj - yi) + xi) inside = !inside;
            }
            return inside;
        }

        /// <summary>This PC's country from Windows region settings, or null.</summary>
        public static string HomeFromWindows()
        {
            try
            {
                var code = RegionInfo.CurrentRegion.TwoLetterISORegionName;
                return CountryPoints.ContainsKey(code) ? code.ToUpperInvariant() : null;
            }
            catch (ArgumentException) { return null; }
        }
    }
}
